//! `srec_parser` — Motorola S-record (SREC) format parser.
//!
//! Implements full parsing of Motorola S-record (`.srec`, `.mot`, `.s19`,
//! `.s28`, `.s37`) files, including:
//!
//! - All SREC record types: S0, S1, S2, S3 (data), S5 (count), S7, S8, S9
//!   (termination), and S4/S6 (reserved).
//! - One's-complement byte-sum checksum verification.
//! - 2-byte (S1/S9), 3-byte (S2/S8), and 4-byte (S3/S7) address fields.
//! - Reconstruction of non-contiguous memory regions.
//! - Contiguous-region merging.
//! - Binary image builder with gap fill.
//! - Encoder: produces SREC output from raw binary.
//!
//! # Record format
//! ```text
//! Sn LL AAAA[AA[AA]] [DD...] CC
//! ```
//! - `n`    — record type digit (0–9)
//! - `LL`   — byte count (address + data + checksum)
//! - `AA..` — address (2, 3, or 4 bytes depending on type)
//! - `DD`   — data bytes
//! - `CC`   — one's-complement of low byte of byte sum
//!
//! # Usage
//! ```rust
//! use rustre_loader_firmware::srec_parser::SrecFile;
//! let data = b"S0030000FC\r\nS1070000DEADBEEFC0\r\nS9030000FC\r\n";
//! let file = SrecFile::parse(data).unwrap();
//! assert!(!file.regions.is_empty());
//! ```

use crate::FirmwareError;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// SrecType
// ─────────────────────────────────────────────────────────────────────────────

/// Motorola S-record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrecType {
    /// S0 — block header record (vendor info, not transferred to memory).
    S0,
    /// S1 — data record with 2-byte (16-bit) address.
    S1,
    /// S2 — data record with 3-byte (24-bit) address.
    S2,
    /// S3 — data record with 4-byte (32-bit) address.
    S3,
    /// S4 — reserved (not used).
    S4,
    /// S5 — record count (16-bit count of S1/S2/S3 records).
    S5,
    /// S6 — record count (24-bit count, rare).
    S6,
    /// S7 — start address for S3 (4-byte address).
    S7,
    /// S8 — start address for S2 (3-byte address).
    S8,
    /// S9 — start address for S1 (2-byte address).
    S9,
    /// Unknown record type digit.
    Unknown(u8),
}

impl SrecType {
    /// Map a digit byte ('0'–'9') to [`SrecType`].
    #[must_use]
    pub const fn from_char(c: u8) -> Self {
        match c {
            b'0' => Self::S0,
            b'1' => Self::S1,
            b'2' => Self::S2,
            b'3' => Self::S3,
            b'4' => Self::S4,
            b'5' => Self::S5,
            b'6' => Self::S6,
            b'7' => Self::S7,
            b'8' => Self::S8,
            b'9' => Self::S9,
            x => Self::Unknown(x),
        }
    }

    /// Return the digit character for this record type.
    #[must_use]
    pub const fn to_char(self) -> u8 {
        match self {
            Self::S0 => b'0',
            Self::S1 => b'1',
            Self::S2 => b'2',
            Self::S3 => b'3',
            Self::S4 => b'4',
            Self::S5 => b'5',
            Self::S6 => b'6',
            Self::S7 => b'7',
            Self::S8 => b'8',
            Self::S9 => b'9',
            Self::Unknown(c) => c,
        }
    }

    /// Number of address bytes for this record type.
    #[must_use]
    pub const fn addr_bytes(self) -> usize {
        match self {
            Self::S0 | Self::S1 | Self::S5 | Self::S9 => 2,
            Self::S2 | Self::S6 | Self::S8 => 3,
            Self::S3 | Self::S7 => 4,
            Self::S4 | Self::Unknown(_) => 0,
        }
    }

    /// Return `true` if this is a data-bearing record (S1/S2/S3).
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(self, Self::S1 | Self::S2 | Self::S3)
    }

    /// Return `true` if this is a termination / start-address record.
    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(self, Self::S7 | Self::S8 | Self::S9)
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::S0 => "S0-header",
            Self::S1 => "S1-data16",
            Self::S2 => "S2-data24",
            Self::S3 => "S3-data32",
            Self::S4 => "S4-reserved",
            Self::S5 => "S5-count16",
            Self::S6 => "S6-count24",
            Self::S7 => "S7-start32",
            Self::S8 => "S8-start24",
            Self::S9 => "S9-start16",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for SrecType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SrecRecord
// ─────────────────────────────────────────────────────────────────────────────

/// One parsed S-record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrecRecord {
    /// Record type.
    pub record_type: SrecType,
    /// Byte count field value (address + data + checksum bytes).
    pub byte_count: u8,
    /// Absolute address (width depends on `record_type`).
    pub address: u64,
    /// Data payload.
    pub data: Vec<u8>,
    /// Checksum byte from the record.
    pub checksum: u8,
}

/// Parse two ASCII-hex chars at `src[off..off+2]`.
fn hex2(src: &[u8], off: usize) -> Result<u8, FirmwareError> {
    if off + 2 > src.len() {
        return Err(FirmwareError::TruncatedData);
    }
    let hi = char::from(src[off]).to_digit(16).ok_or_else(|| {
        FirmwareError::ParseError(format!("non-hex '{}' at {off}", char::from(src[off])))
    })? as u8;
    let lo = char::from(src[off + 1]).to_digit(16).ok_or_else(|| {
        FirmwareError::ParseError(format!(
            "non-hex '{}' at {}",
            char::from(src[off + 1]),
            off + 1
        ))
    })? as u8;
    Ok((hi << 4) | lo)
}

impl SrecRecord {
    /// Parse a single S-record from `line`.
    ///
    /// `line` must start with `'S'` followed by the record type digit.
    /// Trailing CR/LF is stripped.
    pub fn parse_line(line: &[u8]) -> Result<Self, FirmwareError> {
        // Strip trailing CR/LF
        let line = line
            .iter()
            .rposition(|&b| b != b'\r' && b != b'\n')
            .map(|e| &line[..e + 1])
            .unwrap_or(line);

        if line.len() < 4 || line[0] != b'S' {
            return Err(FirmwareError::InvalidMagic(
                "S-record must start with 'S'".to_string(),
            ));
        }
        let rtype = SrecType::from_char(line[1]);
        let addr_bytes = match rtype {
            SrecType::Unknown(c) => {
                return Err(FirmwareError::UnknownRecord(c));
            }
            SrecType::S4 => {
                return Err(FirmwareError::ParseError("S4 is reserved".to_string()));
            }
            t => t.addr_bytes(),
        };

        // hex data starts at line[2]
        let hex = &line[2..];
        let byte_count = hex2(hex, 0)?;

        if (byte_count as usize) < addr_bytes + 1 {
            return Err(FirmwareError::TruncatedData);
        }
        let data_count = byte_count as usize - addr_bytes - 1;

        // Decode address
        let mut address = 0u64;
        for i in 0..addr_bytes {
            address = (address << 8) | u64::from(hex2(hex, 2 + i * 2)?);
        }

        // Decode data bytes
        let data_hex_start = 2 + addr_bytes * 2;
        let data_hex_end = data_hex_start + data_count * 2;
        if data_hex_end + 2 > hex.len() {
            return Err(FirmwareError::TruncatedData);
        }
        let mut data = Vec::with_capacity(data_count);
        for i in 0..data_count {
            data.push(hex2(hex, data_hex_start + i * 2)?);
        }

        let checksum = hex2(hex, data_hex_end)?;

        // Verify checksum: one's-complement of (byte_count + address_bytes + data_bytes) & 0xFF
        let mut sum: u32 = u32::from(byte_count);
        for i in 0..addr_bytes {
            sum += u32::from(hex2(hex, 2 + i * 2)?);
        }
        for &b in &data {
            sum += u32::from(b);
        }
        let expected = (!(sum & 0xFF)) as u8;
        if expected != checksum {
            return Err(FirmwareError::ChecksumMismatch {
                expected,
                actual: checksum,
            });
        }

        Ok(Self {
            record_type: rtype,
            byte_count,
            address,
            data,
            checksum,
        })
    }

    /// Encode this record to Motorola S-record ASCII format.
    #[must_use]
    pub fn to_srec_string(&self) -> String {
        let addr_bytes = self.record_type.addr_bytes();
        let byte_count = addr_bytes + self.data.len() + 1;
        let mut sum: u32 = byte_count as u32;
        // Address bytes
        let mut addr_vec = Vec::with_capacity(addr_bytes);
        for i in (0..addr_bytes).rev() {
            let b = ((self.address >> (i * 8)) & 0xFF) as u8;
            addr_vec.push(b);
            sum += u32::from(b);
        }
        for &b in &self.data {
            sum += u32::from(b);
        }
        let cs = (!(sum & 0xFF)) as u8;

        let mut s = format!(
            "S{}{:02X}",
            char::from(self.record_type.to_char()),
            byte_count
        );
        for b in &addr_vec {
            s.push_str(&format!("{b:02X}"));
        }
        for b in &self.data {
            s.push_str(&format!("{b:02X}"));
        }
        s.push_str(&format!("{cs:02X}"));
        s
    }
}

impl fmt::Display for SrecRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} addr={:#010x} byte_count={} data_len={}",
            self.record_type,
            self.address,
            self.byte_count,
            self.data.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory region
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous region of data at a specific absolute address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrecRegion {
    pub start_addr: u64,
    pub data: Vec<u8>,
}

impl SrecRegion {
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        self.start_addr + self.data.len() as u64
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
}

impl fmt::Display for SrecRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "region [{:#010x}..{:#010x}] ({} bytes)",
            self.start_addr,
            self.end_addr(),
            self.data.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SrecFile
// ─────────────────────────────────────────────────────────────────────────────

/// Assembled result of parsing a complete SREC file.
#[derive(Debug, Clone)]
pub struct SrecFile {
    /// Non-overlapping memory regions in address order.
    pub regions: Vec<SrecRegion>,
    /// Entry / start address from S7/S8/S9 record.
    pub entry_point: Option<u64>,
    /// Header string from S0 record (if present).
    pub header: Option<String>,
    /// Total count of S1/S2/S3 records processed.
    pub data_record_count: usize,
    /// All parsed records in file order.
    pub records: Vec<SrecRecord>,
}

impl SrecFile {
    /// Parse all records from `data` (bytes of an SREC file) and assemble
    /// the memory image.
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        let mut regions: Vec<SrecRegion> = Vec::new();
        let mut entry_point: Option<u64> = None;
        let mut header: Option<String> = None;
        let mut data_record_count = 0usize;
        let mut records: Vec<SrecRecord> = Vec::new();

        for (line_no, raw_line) in data.split(|&b| b == b'\n').enumerate() {
            let line = if raw_line.last() == Some(&b'\r') {
                &raw_line[..raw_line.len() - 1]
            } else {
                raw_line
            };
            if line.is_empty() {
                continue;
            }
            if line[0] != b'S' {
                continue;
            } // skip comments / non-records

            let record = SrecRecord::parse_line(line).map_err(|e| {
                FirmwareError::ParseError(format!("SREC line {}: {e}", line_no + 1))
            })?;

            match record.record_type {
                SrecType::S0 => {
                    // Header: data is a printable string
                    let s = String::from_utf8_lossy(
                        record
                            .data
                            .iter()
                            .copied()
                            .take_while(|&b| b != 0 && b.is_ascii_graphic() || b == b' ')
                            .collect::<Vec<u8>>()
                            .as_slice(),
                    )
                    .to_string();
                    header = Some(s);
                }
                SrecType::S1 | SrecType::S2 | SrecType::S3 => {
                    let addr = record.address;
                    // Merge with last region if contiguous
                    if let Some(last) = regions.last_mut() && last.end_addr() == addr {
                        last.extend(&record.data);
                        data_record_count += 1;
                        records.push(record);
                        continue;
                    }
                    regions.push(SrecRegion {
                        start_addr: addr,
                        data: record.data.clone(),
                    });
                    data_record_count += 1;
                }
                SrecType::S5 => {
                    // Record count verification (optional): address field = count
                    // We don't error on mismatch here but could add a warning.
                }
                SrecType::S7 | SrecType::S8 | SrecType::S9 => {
                    entry_point = Some(record.address);
                }
                _ => {}
            }
            records.push(record);
        }

        // Sort regions by address
        regions.sort_by_key(|r| r.start_addr);

        Ok(Self {
            regions,
            entry_point,
            header,
            data_record_count,
            records,
        })
    }

    /// Build a flat binary image, filling address gaps with `fill_byte`.
    #[must_use]
    pub fn build_binary_image(&self, base: Option<u64>, fill_byte: u8) -> Vec<u8> {
        if self.regions.is_empty() {
            return Vec::new();
        }
        let base = base.unwrap_or_else(|| self.regions[0].start_addr);
        let end = self
            .regions
            .iter()
            .map(SrecRegion::end_addr)
            .max()
            .unwrap_or(base);
        if end <= base {
            return Vec::new();
        }
        // Guard against allocating a multi-gigabyte image from a crafted SREC file.
        // 256 MiB is a generous upper bound for typical firmware images.
        const MAX_IMAGE_SIZE: usize = 256 * 1024 * 1024;
        let size_u64 = end - base;
        if size_u64 > MAX_IMAGE_SIZE as u64 {
            return Vec::new();
        }
        let size = size_u64 as usize;
        let mut img = vec![fill_byte; size];
        for region in &self.regions {
            if region.end_addr() <= base {
                continue;
            }
            let dst_off = region.start_addr.saturating_sub(base) as usize;
            let src_skip = base.saturating_sub(region.start_addr) as usize;
            let bytes = &region.data[src_skip..];
            let copy_len = bytes.len().min(size.saturating_sub(dst_off));
            img[dst_off..dst_off + copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        img
    }

    /// Total data bytes across all regions.
    #[must_use]
    pub fn total_data_bytes(&self) -> usize {
        self.regions.iter().map(SrecRegion::size).sum()
    }

    /// Lowest start address.
    #[must_use]
    pub fn min_address(&self) -> Option<u64> {
        self.regions.iter().map(|r| r.start_addr).min()
    }

    /// Highest end address.
    #[must_use]
    pub fn max_address(&self) -> Option<u64> {
        self.regions.iter().map(SrecRegion::end_addr).max()
    }

    /// Number of address-space gaps.
    #[must_use]
    pub fn gap_count(&self) -> usize {
        if self.regions.len() < 2 {
            return 0;
        }
        self.regions
            .windows(2)
            .filter(|w| w[0].end_addr() < w[1].start_addr)
            .count()
    }

    /// Total gap bytes.
    #[must_use]
    pub fn total_gap_bytes(&self) -> u64 {
        if self.regions.len() < 2 {
            return 0;
        }
        self.regions
            .windows(2)
            .map(|w| w[1].start_addr.saturating_sub(w[0].end_addr()))
            .sum()
    }

    /// Effective entry point.
    #[must_use]
    pub fn effective_entry(&self) -> Option<u64> {
        self.entry_point
            .or_else(|| self.regions.first().map(|r| r.start_addr))
    }

    /// Return `true` if the file appears to use 4-byte (S3/S7) addresses.
    #[must_use]
    pub fn has_32bit_addresses(&self) -> bool {
        self.records
            .iter()
            .any(|r| matches!(r.record_type, SrecType::S3 | SrecType::S7))
    }
}

impl fmt::Display for SrecFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SrecFile regions={} total_bytes={} records={} entry={:?}",
            self.regions.len(),
            self.total_data_bytes(),
            self.data_record_count,
            self.effective_entry(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoder
// ─────────────────────────────────────────────────────────────────────────────

/// Encode raw binary `data` at `base_address` into Motorola S-record format.
///
/// Uses S3 records (4-byte addresses) and an S7 terminator.
/// `bytes_per_record` is clamped to [1, 250].
#[must_use]
pub fn encode_to_srec(data: &[u8], base_address: u32, bytes_per_record: u8) -> String {
    let bpr = (bytes_per_record as usize).max(1).min(250);
    let mut out = String::new();
    let mut record_count: u32 = 0;

    // S0 header record (address = 0, data = "HDR")
    {
        let hdr_data = b"HDR";
        let addr_bytes = 2usize;
        let byte_count = addr_bytes + hdr_data.len() + 1;
        let mut sum: u32 = byte_count as u32;
        // address = 0x0000
        for b in &[0u8, 0] {
            sum += u32::from(*b);
        }
        for &b in hdr_data {
            sum += u32::from(b);
        }
        let cs = (!(sum & 0xFF)) as u8;
        out.push_str(&format!("S0{byte_count:02X}0000"));
        for b in hdr_data {
            out.push_str(&format!("{b:02X}"));
        }
        out.push_str(&format!("{cs:02X}\r\n"));
    }

    // S3 data records
    for (chunk_idx, chunk) in data.chunks(bpr).enumerate() {
        let addr = u64::from(base_address) + (chunk_idx as u64).saturating_mul(bpr as u64);
        let addr_bytes = 4usize;
        let byte_count = addr_bytes + chunk.len() + 1;
        let mut sum: u32 = byte_count as u32;
        let addr_be = [
            (addr >> 24) as u8,
            (addr >> 16) as u8,
            (addr >> 8) as u8,
            addr as u8,
        ];
        for &b in &addr_be {
            sum += u32::from(b);
        }
        for &b in chunk {
            sum += u32::from(b);
        }
        let cs = (!(sum & 0xFF)) as u8;
        out.push_str(&format!("S3{byte_count:02X}"));
        for b in &addr_be {
            out.push_str(&format!("{b:02X}"));
        }
        for b in chunk {
            out.push_str(&format!("{b:02X}"));
        }
        out.push_str(&format!("{cs:02X}\r\n"));
        record_count += 1;
    }

    // S5 record count record
    {
        let byte_count = 3u8;
        let mut sum: u32 = u32::from(byte_count);
        let rc_hi = (record_count >> 8) as u8;
        let rc_lo = (record_count & 0xFF) as u8;
        sum += u32::from(rc_hi) + u32::from(rc_lo);
        let cs = (!(sum & 0xFF)) as u8;
        out.push_str(&format!(
            "S5{byte_count:02X}{record_count:04X}{cs:02X}\r\n"
        ));
    }

    // S7 terminator (entry point = base_address)
    {
        let byte_count = 5u8;
        let mut sum: u32 = u32::from(byte_count);
        let ep_be = [
            (base_address >> 24) as u8,
            (base_address >> 16) as u8,
            (base_address >> 8) as u8,
            base_address as u8,
        ];
        for &b in &ep_be {
            sum += u32::from(b);
        }
        let cs = (!(sum & 0xFF)) as u8;
        out.push_str(&format!("S7{byte_count:02X}"));
        for b in &ep_be {
            out.push_str(&format!("{b:02X}"));
        }
        out.push_str(&format!("{cs:02X}\r\n"));
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_s1(addr: u16, data: &[u8]) -> Vec<u8> {
        let addr_bytes = 2usize;
        let byte_count = addr_bytes + data.len() + 1;
        let mut sum: u32 = byte_count as u32;
        let ah = (addr >> 8) as u8;
        let al = addr as u8;
        sum += ah as u32 + al as u32;
        for &b in data {
            sum += b as u32;
        }
        let cs = (!(sum & 0xFF)) as u8;
        let mut line = format!("S1{:02X}{:04X}", byte_count, addr);
        for b in data {
            line.push_str(&format!("{b:02X}"));
        }
        line.push_str(&format!("{cs:02X}"));
        line.into_bytes()
    }

    fn make_s3(addr: u32, data: &[u8]) -> Vec<u8> {
        let addr_bytes = 4usize;
        let byte_count = addr_bytes + data.len() + 1;
        let mut sum: u32 = byte_count as u32;
        let ab = [
            (addr >> 24) as u8,
            (addr >> 16) as u8,
            (addr >> 8) as u8,
            addr as u8,
        ];
        for &b in &ab {
            sum += b as u32;
        }
        for &b in data {
            sum += b as u32;
        }
        let cs = (!(sum & 0xFF)) as u8;
        let mut line = format!("S3{:02X}{:08X}", byte_count, addr);
        for b in data {
            line.push_str(&format!("{b:02X}"));
        }
        line.push_str(&format!("{cs:02X}"));
        line.into_bytes()
    }

    fn make_s9(addr: u16) -> Vec<u8> {
        let byte_count = 3u8;
        let mut sum: u32 = byte_count as u32;
        sum += (addr >> 8) as u32 + (addr & 0xFF) as u32;
        let cs = (!(sum & 0xFF)) as u8;
        format!("S9{:02X}{:04X}{:02X}", byte_count, addr, cs).into_bytes()
    }

    // ── SrecType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_srec_type_from_char() {
        assert_eq!(SrecType::from_char(b'1'), SrecType::S1);
        assert_eq!(SrecType::from_char(b'3'), SrecType::S3);
        assert_eq!(SrecType::from_char(b'9'), SrecType::S9);
    }

    #[test]
    fn test_srec_type_to_char_round_trip() {
        for c in b"0123456789".iter().copied() {
            let t = SrecType::from_char(c);
            assert_eq!(t.to_char(), c);
        }
    }

    #[test]
    fn test_srec_type_unknown() {
        let t = SrecType::from_char(b'Z');
        assert_eq!(t.to_char(), b'Z');
        assert_eq!(t.name(), "unknown");
    }

    #[test]
    fn test_srec_type_addr_bytes() {
        assert_eq!(SrecType::S1.addr_bytes(), 2);
        assert_eq!(SrecType::S2.addr_bytes(), 3);
        assert_eq!(SrecType::S3.addr_bytes(), 4);
        assert_eq!(SrecType::S9.addr_bytes(), 2);
        assert_eq!(SrecType::S7.addr_bytes(), 4);
    }

    #[test]
    fn test_srec_type_is_data() {
        assert!(SrecType::S1.is_data());
        assert!(SrecType::S2.is_data());
        assert!(SrecType::S3.is_data());
        assert!(!SrecType::S0.is_data());
        assert!(!SrecType::S9.is_data());
    }

    #[test]
    fn test_srec_type_is_terminator() {
        assert!(SrecType::S7.is_terminator());
        assert!(SrecType::S8.is_terminator());
        assert!(SrecType::S9.is_terminator());
        assert!(!SrecType::S1.is_terminator());
    }

    #[test]
    fn test_srec_type_display() {
        assert_eq!(SrecType::S3.to_string(), "S3-data32");
        assert_eq!(SrecType::S9.to_string(), "S9-start16");
    }

    // ── SrecRecord::parse_line ────────────────────────────────────────────────

    #[test]
    fn test_parse_s1_record() {
        let line = make_s1(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let rec = SrecRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, SrecType::S1);
        assert_eq!(rec.address, 0x1000);
        assert_eq!(&rec.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_s3_record() {
        let line = make_s3(0x8000_0000, &[0xAA, 0xBB]);
        let rec = SrecRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, SrecType::S3);
        assert_eq!(rec.address, 0x8000_0000);
        assert_eq!(&rec.data, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_s9_terminator() {
        let line = make_s9(0x0000);
        let rec = SrecRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, SrecType::S9);
        assert!(rec.data.is_empty());
        assert_eq!(rec.address, 0x0000);
    }

    #[test]
    fn test_parse_bad_checksum() {
        let mut line = make_s1(0x0000, &[0x01, 0x02]);
        // Corrupt the last two bytes (checksum)
        let len = line.len();
        line[len - 2] = b'0';
        line[len - 1] = b'0';
        assert!(SrecRecord::parse_line(&line).is_err());
    }

    #[test]
    fn test_parse_missing_s() {
        assert!(SrecRecord::parse_line(b"10300000AABBCC").is_err());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(SrecRecord::parse_line(b"S1").is_err());
    }

    #[test]
    fn test_parse_strips_crlf() {
        let mut line = make_s9(0);
        line.push(b'\r');
        line.push(b'\n');
        assert!(SrecRecord::parse_line(&line).is_ok());
    }

    // ── to_srec_string round-trip ──────────────────────────────────────────────

    #[test]
    fn test_record_round_trip_s1() {
        let orig_line = make_s1(0x0400, &[0x11, 0x22, 0x33]);
        let rec = SrecRecord::parse_line(&orig_line).unwrap();
        let encoded = rec.to_srec_string();
        let reparsed = SrecRecord::parse_line(encoded.as_bytes()).unwrap();
        assert_eq!(reparsed.address, rec.address);
        assert_eq!(reparsed.data, rec.data);
    }

    #[test]
    fn test_record_round_trip_s3() {
        let orig_line = make_s3(0x0800_1000, &[0xCA, 0xFE]);
        let rec = SrecRecord::parse_line(&orig_line).unwrap();
        let encoded = rec.to_srec_string();
        let reparsed = SrecRecord::parse_line(encoded.as_bytes()).unwrap();
        assert_eq!(reparsed.address, 0x0800_1000);
    }

    // ── SrecFile::parse ───────────────────────────────────────────────────────

    #[test]
    fn test_file_parse_simple() {
        let mut srec = make_s1(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0x1000));
        srec.push(b'\n');
        let file = SrecFile::parse(&srec).unwrap();
        assert_eq!(file.regions.len(), 1);
        assert_eq!(file.regions[0].start_addr, 0x1000);
        assert_eq!(file.entry_point, Some(0x1000));
    }

    #[test]
    fn test_file_parse_two_regions() {
        let mut srec = make_s1(0x0000, &[0x01]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s1(0x0100, &[0x02]));
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        srec.push(b'\n');
        let file = SrecFile::parse(&srec).unwrap();
        assert_eq!(file.regions.len(), 2);
        assert_eq!(file.gap_count(), 1);
    }

    #[test]
    fn test_file_parse_contiguous_merge() {
        let mut srec = make_s1(0x0000, &[0x01, 0x02]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s1(0x0002, &[0x03, 0x04]));
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        srec.push(b'\n');
        let file = SrecFile::parse(&srec).unwrap();
        assert_eq!(file.regions.len(), 1);
        assert_eq!(file.regions[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_file_s3_records() {
        let mut srec = make_s3(0x0800_0000, &[0xAA, 0xBB]);
        srec.push(b'\n');
        srec.extend_from_slice(b"S70500000000FA\r\n"); // S7 with entry = 0
        let file = SrecFile::parse(&srec).unwrap();
        assert!(file.has_32bit_addresses());
        assert_eq!(file.regions[0].start_addr, 0x0800_0000);
    }

    // ── build_binary_image ────────────────────────────────────────────────────

    #[test]
    fn test_build_binary_image_simple() {
        let mut srec = make_s1(0x0000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        let file = SrecFile::parse(&srec).unwrap();
        let img = file.build_binary_image(Some(0), 0xFF);
        assert_eq!(img, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_build_binary_image_fills_gap() {
        let mut srec = make_s1(0x0000, &[0x01]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s1(0x0004, &[0x02]));
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        let file = SrecFile::parse(&srec).unwrap();
        let img = file.build_binary_image(Some(0), 0x00);
        assert_eq!(img, vec![0x01, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_build_binary_image_empty() {
        let file = SrecFile {
            regions: vec![],
            entry_point: None,
            header: None,
            data_record_count: 0,
            records: vec![],
        };
        assert!(file.build_binary_image(None, 0xFF).is_empty());
    }

    // ── encode / round-trip ───────────────────────────────────────────────────

    #[test]
    fn test_encode_and_parse_round_trip() {
        let original = vec![0xCAu8, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78];
        let encoded = encode_to_srec(&original, 0x0000_0000, 4);
        let parsed = SrecFile::parse(encoded.as_bytes()).unwrap();
        let rebuilt = parsed.build_binary_image(Some(0), 0x00);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn test_encode_contains_s7() {
        let encoded = encode_to_srec(&[0xAA], 0x1000_0000, 16);
        assert!(encoded.contains("S7"));
    }

    #[test]
    fn test_encode_contains_s0() {
        let encoded = encode_to_srec(&[0xBB], 0x0000, 16);
        assert!(encoded.contains("S0"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn test_min_max_address() {
        let mut srec = make_s1(0x0010, &[0xAA]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s1(0x0050, &[0xBB]));
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        let file = SrecFile::parse(&srec).unwrap();
        assert_eq!(file.min_address(), Some(0x10));
        assert_eq!(file.max_address(), Some(0x51));
    }

    #[test]
    fn test_total_gap_bytes() {
        let mut srec = make_s1(0x0000, &[0x01, 0x02]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s1(0x0008, &[0x03]));
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        let file = SrecFile::parse(&srec).unwrap();
        assert_eq!(file.total_gap_bytes(), 6);
    }

    #[test]
    fn test_effective_entry_from_s9() {
        let mut srec = make_s1(0x0200, &[0xAA]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0x0200));
        let file = SrecFile::parse(&srec).unwrap();
        assert_eq!(file.effective_entry(), Some(0x0200));
    }

    #[test]
    fn test_display() {
        let mut srec = make_s1(0x0000, &[0x01, 0x02, 0x03]);
        srec.push(b'\n');
        srec.extend_from_slice(&make_s9(0));
        let file = SrecFile::parse(&srec).unwrap();
        let s = file.to_string();
        assert!(s.contains("regions=1"));
        assert!(s.contains("total_bytes=3"));
    }

    #[test]
    fn test_srec_region_display() {
        let r = SrecRegion {
            start_addr: 0x2000,
            data: vec![0u8; 128],
        };
        let s = r.to_string();
        assert!(s.contains("0x00002000"));
        assert!(s.contains("128 bytes"));
    }

    #[test]
    fn test_record_display() {
        let line = make_s1(0x0400, &[0x11, 0x22]);
        let rec = SrecRecord::parse_line(&line).unwrap();
        let s = rec.to_string();
        assert!(s.contains("S1-data16"));
        assert!(s.contains("0x00000400"));
    }
}
