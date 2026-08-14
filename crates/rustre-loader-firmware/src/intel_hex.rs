//! `intel_hex` — Intel HEX format parser.
//!
//! Implements full parsing of Intel HEX (`.hex`, `.ihex`) files including:
//! - All six record types (Data, EndOfFile, ExtSegAddr, StartSegAddr,
//!   ExtLinAddr, StartLinAddr)
//! - Checksum verification for every record
//! - Reconstruction of a binary memory image (with configurable gap-fill byte)
//! - Multi-region output for non-contiguous address maps
//! - Contiguous-region merging
//!
//! # Record format
//! ```text
//! :LLAAAATT[DD...]CC
//! ```
//! - `LL`   — byte count of data field
//! - `AAAA` — 16-bit offset address
//! - `TT`   — record type (00–05)
//! - `DD`   — data bytes
//! - `CC`   — two's-complement checksum
//!
//! # Usage
//! ```rust
//! use rustre_loader_firmware::intel_hex::IhexFile;
//! let hex = b":100000001027000010270000102700001027000014\r\n:00000001FF\r\n";
//! let file = IhexFile::parse(hex).unwrap();
//! assert!(!file.regions.is_empty());
//! ```

use crate::FirmwareError;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Record type enum
// ─────────────────────────────────────────────────────────────────────────────

/// Intel HEX record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IhexType {
    /// Record type 00: binary data.
    Data,
    /// Record type 01: end of file (empty data field).
    EndOfFile,
    /// Record type 02: 20-bit extended segment base address.
    ExtSegAddr,
    /// Record type 03: x86 CS:IP start address.
    StartSegAddr,
    /// Record type 04: 32-bit extended linear base address (upper 16 bits).
    ExtLinAddr,
    /// Record type 05: 32-bit absolute start address (EIP).
    StartLinAddr,
    /// Unrecognised record type.
    Unknown(u8),
}

impl IhexType {
    /// Map a raw byte to the corresponding [`IhexType`].
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Data,
            0x01 => Self::EndOfFile,
            0x02 => Self::ExtSegAddr,
            0x03 => Self::StartSegAddr,
            0x04 => Self::ExtLinAddr,
            0x05 => Self::StartLinAddr,
            x => Self::Unknown(x),
        }
    }

    /// Return the raw record type byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Data => 0x00,
            Self::EndOfFile => 0x01,
            Self::ExtSegAddr => 0x02,
            Self::StartSegAddr => 0x03,
            Self::ExtLinAddr => 0x04,
            Self::StartLinAddr => 0x05,
            Self::Unknown(b) => b,
        }
    }

    /// Return a short human-readable name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::EndOfFile => "EOF",
            Self::ExtSegAddr => "EXT_SEG_ADDR",
            Self::StartSegAddr => "START_SEG_ADDR",
            Self::ExtLinAddr => "EXT_LIN_ADDR",
            Self::StartLinAddr => "START_LIN_ADDR",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for IhexType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IhexRecord
// ─────────────────────────────────────────────────────────────────────────────

/// One parsed Intel HEX record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IhexRecord {
    /// Number of data bytes declared in the record.
    pub byte_count: u8,
    /// 16-bit base address (meaning depends on record type).
    pub address: u16,
    /// Record type.
    pub record_type: IhexType,
    /// Data payload bytes.
    pub data: Vec<u8>,
    /// Checksum byte from the record.
    pub checksum: u8,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Parse two ASCII hex chars at `src[off..off+2]` into a `u8`.
fn hex2(src: &[u8], off: usize) -> Result<u8, FirmwareError> {
    if off + 2 > src.len() {
        return Err(FirmwareError::TruncatedData);
    }
    let hi = char::from(src[off]).to_digit(16).ok_or_else(|| {
        FirmwareError::ParseError(format!(
            "non-hex char '{}' at byte {off}",
            char::from(src[off])
        ))
    })? as u8;
    let lo = char::from(src[off + 1]).to_digit(16).ok_or_else(|| {
        FirmwareError::ParseError(format!(
            "non-hex char '{}' at byte {}",
            char::from(src[off + 1]),
            off + 1
        ))
    })? as u8;
    Ok((hi << 4) | lo)
}

impl IhexRecord {
    /// Parse a single Intel HEX record from `line`.
    ///
    /// `line` must start with `':'`.  Trailing `'\r'` and `'\n'` are ignored.
    pub fn parse_line(line: &[u8]) -> Result<Self, FirmwareError> {
        // Strip trailing CR/LF
        let line = line
            .iter()
            .rposition(|&b| b != b'\r' && b != b'\n')
            .map(|end| &line[..end + 1])
            .unwrap_or(line);

        if line.is_empty() || line[0] != b':' {
            return Err(FirmwareError::InvalidMagic(
                "Intel HEX record must start with ':'".to_string(),
            ));
        }
        let hex = &line[1..];
        // Minimum: LL(2) + AAAA(4) + TT(2) + CC(2) = 10 chars
        if hex.len() < 10 {
            return Err(FirmwareError::TruncatedData);
        }
        let byte_count = hex2(hex, 0)?;
        let addr_hi = hex2(hex, 2)? as u16;
        let addr_lo = hex2(hex, 4)? as u16;
        let address = (addr_hi << 8) | addr_lo;
        let rt_byte = hex2(hex, 6)?;
        let record_type = IhexType::from_byte(rt_byte);

        // Data field starts at offset 8, two chars per byte
        let data_hex_start = 8usize;
        let data_hex_end = data_hex_start + byte_count as usize * 2;
        if data_hex_end + 2 > hex.len() {
            return Err(FirmwareError::TruncatedData);
        }
        let mut data = Vec::with_capacity(byte_count as usize);
        for i in 0..byte_count as usize {
            data.push(hex2(hex, data_hex_start + i * 2)?);
        }
        let checksum = hex2(hex, data_hex_end)?;

        // Verify two's-complement checksum:
        // sum(byte_count, addr_hi, addr_lo, record_type, data..., checksum) & 0xFF == 0
        let mut sum: u8 = 0;
        sum = sum.wrapping_add(byte_count);
        sum = sum.wrapping_add((address >> 8) as u8);
        sum = sum.wrapping_add(address as u8);
        sum = sum.wrapping_add(rt_byte);
        for &b in &data {
            sum = sum.wrapping_add(b);
        }
        sum = sum.wrapping_add(checksum);
        if sum != 0 {
            return Err(FirmwareError::ChecksumMismatch {
                expected: 0,
                actual: sum,
            });
        }

        Ok(Self {
            byte_count,
            address,
            record_type,
            data,
            checksum,
        })
    }

    /// Encode this record to Intel HEX format (includes leading `':'`).
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        let mut sum: u8 = 0;
        sum = sum.wrapping_add(self.byte_count);
        sum = sum.wrapping_add((self.address >> 8) as u8);
        sum = sum.wrapping_add(self.address as u8);
        sum = sum.wrapping_add(self.record_type.to_byte());
        for &b in &self.data {
            sum = sum.wrapping_add(b);
        }
        let checksum = (!sum).wrapping_add(1);
        let mut s = format!(
            ":{:02X}{:04X}{:02X}",
            self.byte_count,
            self.address,
            self.record_type.to_byte(),
        );
        for b in &self.data {
            s.push_str(&format!("{b:02X}"));
        }
        s.push_str(&format!("{checksum:02X}"));
        s
    }
}

impl fmt::Display for IhexRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} addr={:#06x} len={} cs={:#04x}",
            self.record_type, self.address, self.byte_count, self.checksum,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory region
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous region of binary data at a specific absolute address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRegion {
    /// Absolute (32-bit) start address.
    pub start_addr: u64,
    /// Raw bytes.
    pub data: Vec<u8>,
}

impl MemRegion {
    #[must_use]
    pub fn end_addr(&self) -> u64 {
        self.start_addr + self.data.len() as u64
    }

    /// Return `true` if `addr` falls within this region.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr < self.end_addr()
    }

    /// Append `bytes` to this region; the caller must ensure contiguity.
    pub fn extend(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Display for MemRegion {
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
// IhexFile
// ─────────────────────────────────────────────────────────────────────────────

/// Assembled result of parsing a complete Intel HEX file.
#[derive(Debug, Clone)]
pub struct IhexFile {
    /// Non-overlapping memory regions in address order.
    pub regions: Vec<MemRegion>,
    /// Start address from record type 04 + 00 or type 05.
    pub start_address: Option<u64>,
    /// All parsed records in file order.
    pub records: Vec<IhexRecord>,
}

impl IhexFile {
    /// Parse all records from `data` (bytes of a `.hex` file) and assemble
    /// the memory image.
    ///
    /// Lines may be separated by `\n` or `\r\n`.
    /// Blank lines are skipped.
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        let mut records = Vec::new();
        let mut upper_base: u64 = 0;
        let mut start_address: Option<u64> = None;
        let mut regions: Vec<MemRegion> = Vec::new();

        for (line_no, raw_line) in data.split(|&b| b == b'\n').enumerate() {
            // Strip CR if present
            let line = if raw_line.last() == Some(&b'\r') {
                &raw_line[..raw_line.len() - 1]
            } else {
                raw_line
            };
            if line.is_empty() {
                continue;
            }
            if line[0] != b':' {
                // Skip lines that aren't records (comments, etc.)
                continue;
            }

            let record = IhexRecord::parse_line(line)
                .map_err(|e| FirmwareError::ParseError(format!("line {}: {e}", line_no + 1)))?;

            match record.record_type {
                IhexType::Data => {
                    let abs_addr = upper_base + record.address as u64;
                    // Try to merge into the last region if contiguous
                    if let Some(last) = regions.last_mut() && last.end_addr() == abs_addr {
                        last.extend(&record.data);
                        records.push(record);
                        continue;
                    }
                    regions.push(MemRegion {
                        start_addr: abs_addr,
                        data: record.data.clone(),
                    });
                }
                IhexType::EndOfFile => {
                    records.push(record);
                    break;
                }
                IhexType::ExtLinAddr => {
                    if record.data.len() < 2 {
                        return Err(FirmwareError::TruncatedData);
                    }
                    let upper = u16::from_be_bytes([record.data[0], record.data[1]]) as u64;
                    upper_base = upper << 16;
                }
                IhexType::ExtSegAddr => {
                    if record.data.len() < 2 {
                        return Err(FirmwareError::TruncatedData);
                    }
                    let seg = u16::from_be_bytes([record.data[0], record.data[1]]) as u64;
                    upper_base = seg * 16;
                }
                IhexType::StartLinAddr => {
                    if record.data.len() >= 4 {
                        start_address = Some(u32::from_be_bytes([
                            record.data[0],
                            record.data[1],
                            record.data[2],
                            record.data[3],
                        ]) as u64);
                    }
                }
                IhexType::StartSegAddr => {
                    if record.data.len() >= 4 {
                        let cs = u16::from_be_bytes([record.data[0], record.data[1]]) as u64;
                        let ip = u16::from_be_bytes([record.data[2], record.data[3]]) as u64;
                        start_address = Some((cs << 4).wrapping_add(ip));
                    }
                }
                IhexType::Unknown(rt) => {
                    return Err(FirmwareError::UnknownRecord(rt));
                }
            }
            records.push(record);
        }

        // Sort regions by address
        regions.sort_by_key(|r| r.start_addr);

        Ok(Self {
            regions,
            start_address,
            records,
        })
    }

    /// Build a single flat binary image, filling address gaps with `fill_byte`.
    ///
    /// `base` sets the start address; bytes before `base` are omitted.
    /// If `base` is `None`, the lowest region start address is used.
    #[must_use]
    pub fn build_binary_image(&self, base: Option<u64>, fill_byte: u8) -> Vec<u8> {
        if self.regions.is_empty() {
            return Vec::new();
        }
        let base = base.unwrap_or_else(|| self.regions[0].start_addr);
        let end = self
            .regions
            .iter()
            .map(|r| r.end_addr())
            .max()
            .unwrap_or(base);
        if end <= base {
            return Vec::new();
        }
        // Guard against allocating a multi-gigabyte image from a crafted HEX file.
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
            let dst = (region.start_addr.saturating_sub(base)) as usize;
            let src_skip = base.saturating_sub(region.start_addr) as usize;
            let bytes = &region.data[src_skip..];
            let copy_len = bytes.len().min(size - dst.min(size));
            img[dst..dst + copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        img
    }

    /// Return the lowest start address across all regions.
    #[must_use]
    pub fn min_address(&self) -> Option<u64> {
        self.regions.iter().map(|r| r.start_addr).min()
    }

    /// Return the highest end address across all regions.
    #[must_use]
    pub fn max_address(&self) -> Option<u64> {
        self.regions.iter().map(|r| r.end_addr()).max()
    }

    /// Total number of data bytes across all regions.
    #[must_use]
    pub fn total_data_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.size()).sum()
    }

    /// Number of address-space gaps between regions.
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

    /// Total size of address-space gaps in bytes.
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

    /// Return the effective entry point: `start_address` if set, or the first
    /// region's start address.
    #[must_use]
    pub fn entry_point(&self) -> Option<u64> {
        self.start_address
            .or_else(|| self.regions.first().map(|r| r.start_addr))
    }
}

impl fmt::Display for IhexFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IhexFile regions={} total_bytes={} gaps={} entry={:?}",
            self.regions.len(),
            self.total_data_bytes(),
            self.gap_count(),
            self.entry_point(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder / encoder helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Intel HEX checksum for a record body (before appending the
/// checksum byte itself).
///
/// `body` must contain: [byte_count, addr_hi, addr_lo, record_type, data...].
#[must_use]
pub fn ihex_checksum(body: &[u8]) -> u8 {
    let sum: u8 = body.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    (!sum).wrapping_add(1)
}

/// Encode raw binary `data` starting at `base_address` into Intel HEX records.
///
/// `records_per_line` bytes of data per DATA record (max 255, default 16).
#[must_use]
pub fn encode_to_ihex(data: &[u8], base_address: u32, bytes_per_record: u8) -> String {
    let bpr = (bytes_per_record as usize).max(1).min(255);
    let mut out = String::new();

    // Emit Extended Linear Address record for the upper 16 bits
    let upper = ((base_address >> 16) & 0xFFFF) as u16;
    {
        let body: [u8; 6] = [
            0x02,
            0x00,
            0x00, // address field = 0
            0x04, // record type ExtLinAddr
            (upper >> 8) as u8,
            upper as u8,
        ];
        let cs = ihex_checksum(&body);
        out.push_str(&format!(":02000004{:04X}{:02X}\r\n", upper, cs,));
    }

    // DATA records
    let lower_base = (base_address & 0xFFFF) as u64;
    for (chunk_idx, chunk) in data.chunks(bpr).enumerate() {
        // Use u64 arithmetic throughout; chunk_idx and bpr are both bounded by
        // data.len() (<=usize::MAX) but the product must not overflow u64 on 64-bit
        // targets, which is safe because usize::MAX * usize::MAX < u128::MAX and
        // we operate in u64 (max data 16 EiB, well within range for real firmware).
        let offset_u64 = (chunk_idx as u64).saturating_mul(bpr as u64);
        let addr16 = ((lower_base.saturating_add(offset_u64)) & 0xFFFF) as u16;
        let mut body = Vec::with_capacity(4 + chunk.len());
        body.push(chunk.len() as u8);
        body.push((addr16 >> 8) as u8);
        body.push(addr16 as u8);
        body.push(0x00); // record type DATA
        body.extend_from_slice(chunk);
        let cs = ihex_checksum(&body);
        out.push(':');
        for b in &body {
            out.push_str(&format!("{b:02X}"));
        }
        out.push_str(&format!("{cs:02X}\r\n"));
    }

    // EOF record
    out.push_str(":00000001FF\r\n");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_line(addr: u16, rtype: u8, data: &[u8]) -> Vec<u8> {
        let mut body = vec![
            data.len() as u8,
            (addr >> 8) as u8,
            (addr & 0xFF) as u8,
            rtype,
        ];
        body.extend_from_slice(data);
        let cs = ihex_checksum(&body);
        body.push(cs);
        let mut line = b":".to_vec();
        for b in &body {
            line.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        line
    }

    fn eof_line() -> Vec<u8> {
        make_line(0, 0x01, &[])
    }

    // ── IhexType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_ihex_type_round_trip() {
        for b in 0u8..=5 {
            let t = IhexType::from_byte(b);
            assert_eq!(t.to_byte(), b);
        }
    }

    #[test]
    fn test_ihex_type_unknown() {
        let t = IhexType::from_byte(0xFF);
        assert_eq!(t.to_byte(), 0xFF);
        assert_eq!(t.name(), "UNKNOWN");
    }

    #[test]
    fn test_ihex_type_display() {
        assert_eq!(IhexType::Data.to_string(), "DATA");
        assert_eq!(IhexType::EndOfFile.to_string(), "EOF");
        assert_eq!(IhexType::ExtLinAddr.to_string(), "EXT_LIN_ADDR");
    }

    // ── checksum ──────────────────────────────────────────────────────────────

    #[test]
    fn test_ihex_checksum_eof() {
        // :00000001FF — body = [0x00, 0x00, 0x00, 0x01], checksum = 0xFF
        let body = [0x00u8, 0x00, 0x00, 0x01];
        assert_eq!(ihex_checksum(&body), 0xFF);
    }

    #[test]
    fn test_ihex_checksum_data_line() {
        // :10000000102700001027000010270000102700007B
        // Sum of first 20 bytes: 0x10+0+0+0+4*0x10+4*0x27 = 0x85 → CS = 0x7B
        let body: Vec<u8> = {
            let mut v = vec![0x10u8, 0x00, 0x00, 0x00];
            v.extend_from_slice(&[0x10, 0x27, 0x00, 0x00].repeat(4));
            v
        };
        // Bug fix: sum = 0x10 + 4*0x10 + 4*0x27 = 0xEC, two's complement = 0x14 (= 20)
        assert_eq!(ihex_checksum(&body), 0x14);
    }

    // ── IhexRecord::parse_line ────────────────────────────────────────────────

    #[test]
    fn test_parse_data_record() {
        let line = make_line(0x0100, 0x00, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let rec = IhexRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, IhexType::Data);
        assert_eq!(rec.address, 0x0100);
        assert_eq!(&rec.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(rec.byte_count, 4);
    }

    #[test]
    fn test_parse_eof_record() {
        let line = eof_line();
        let rec = IhexRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, IhexType::EndOfFile);
        assert!(rec.data.is_empty());
    }

    #[test]
    fn test_parse_ext_lin_addr() {
        let line = make_line(0x0000, 0x04, &[0x08, 0x00]);
        let rec = IhexRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, IhexType::ExtLinAddr);
        assert_eq!(&rec.data, &[0x08, 0x00]);
    }

    #[test]
    fn test_parse_ext_seg_addr() {
        let line = make_line(0x0000, 0x02, &[0x12, 0x34]);
        let rec = IhexRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, IhexType::ExtSegAddr);
    }

    #[test]
    fn test_parse_start_lin_addr() {
        let line = make_line(0x0000, 0x05, &[0x00, 0x00, 0x10, 0x00]);
        let rec = IhexRecord::parse_line(&line).unwrap();
        assert_eq!(rec.record_type, IhexType::StartLinAddr);
    }

    #[test]
    fn test_parse_bad_checksum() {
        let mut line = make_line(0x0000, 0x00, &[0xAA, 0xBB]);
        // Corrupt last two bytes (checksum field)
        let len = line.len();
        line[len - 2] = b'0';
        line[len - 1] = b'0';
        assert!(IhexRecord::parse_line(&line).is_err());
    }

    #[test]
    fn test_parse_missing_colon() {
        assert!(IhexRecord::parse_line(b"10000000DEADBEEF").is_err());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(IhexRecord::parse_line(b":000").is_err());
    }

    #[test]
    fn test_parse_strips_crlf() {
        let mut line = make_line(0, 0x01, &[]);
        line.push(b'\r');
        line.push(b'\n');
        assert!(IhexRecord::parse_line(&line).is_ok());
    }

    // ── to_hex_string round-trip ───────────────────────────────────────────────

    #[test]
    fn test_record_to_hex_string_eof() {
        let rec = IhexRecord {
            byte_count: 0,
            address: 0,
            record_type: IhexType::EndOfFile,
            data: vec![],
            checksum: 0xFF,
        };
        let s = rec.to_hex_string();
        assert!(s.starts_with(':'));
        // Parse it back
        let reparsed = IhexRecord::parse_line(s.as_bytes()).unwrap();
        assert_eq!(reparsed.record_type, IhexType::EndOfFile);
    }

    #[test]
    fn test_record_to_hex_string_data() {
        let payload = [0x11u8, 0x22, 0x33, 0x44];
        let body = {
            let mut v = vec![payload.len() as u8, 0x00, 0x00, 0x00];
            v.extend_from_slice(&payload);
            v
        };
        let cs = ihex_checksum(&body);
        let rec = IhexRecord {
            byte_count: 4,
            address: 0x0000,
            record_type: IhexType::Data,
            data: payload.to_vec(),
            checksum: cs,
        };
        let s = rec.to_hex_string();
        let reparsed = IhexRecord::parse_line(s.as_bytes()).unwrap();
        assert_eq!(&reparsed.data, &payload);
    }

    // ── IhexFile::parse ───────────────────────────────────────────────────────

    #[test]
    fn test_file_parse_single_region() {
        let mut hex = make_line(0x0000, 0x00, &[0x01, 0x02, 0x03, 0x04]);
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.regions.len(), 1);
        assert_eq!(file.regions[0].start_addr, 0);
        assert_eq!(file.regions[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_file_parse_ext_lin_addr_sets_upper() {
        let mut hex = make_line(0x0000, 0x04, &[0x08, 0x00]); // upper = 0x0800_0000
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0000, 0x00, &[0xAA, 0xBB]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.regions[0].start_addr, 0x0800_0000);
    }

    #[test]
    fn test_file_parse_ext_seg_addr() {
        // seg = 0x1000 → upper_base = 0x1000 * 16 = 0x10000
        let mut hex = make_line(0x0000, 0x02, &[0x10, 0x00]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0000, 0x00, &[0xCC]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.regions[0].start_addr, 0x10000);
    }

    #[test]
    fn test_file_parse_start_lin_addr() {
        let mut hex = make_line(0x0000, 0x05, &[0x00, 0x00, 0x80, 0x00]);
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.start_address, Some(0x0000_8000));
    }

    #[test]
    fn test_file_parse_two_non_contiguous_regions() {
        let mut hex = make_line(0x0000, 0x00, &[0x01, 0x02]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0100, 0x00, &[0xAA, 0xBB]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.regions.len(), 2);
        assert_eq!(file.gap_count(), 1);
    }

    #[test]
    fn test_file_parse_contiguous_merge() {
        // Two records that are contiguous → should merge into one region
        let mut hex = make_line(0x0000, 0x00, &[0x01, 0x02]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0002, 0x00, &[0x03, 0x04]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.regions.len(), 1);
        assert_eq!(file.regions[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    // ── build_binary_image ────────────────────────────────────────────────────

    #[test]
    fn test_build_binary_image_simple() {
        let mut hex = make_line(0x0000, 0x00, &[0xDE, 0xAD, 0xBE, 0xEF]);
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        let img = file.build_binary_image(Some(0), 0xFF);
        assert_eq!(img, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_build_binary_image_fills_gap() {
        let mut hex = make_line(0x0000, 0x00, &[0x01]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0004, 0x00, &[0x02]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        let img = file.build_binary_image(Some(0), 0x00);
        assert_eq!(img, vec![0x01, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_build_binary_image_empty() {
        let file = IhexFile {
            regions: vec![],
            start_address: None,
            records: vec![],
        };
        assert!(file.build_binary_image(None, 0xFF).is_empty());
    }

    // ── helper methods ────────────────────────────────────────────────────────

    #[test]
    fn test_min_max_address() {
        let mut hex = make_line(0x0010, 0x00, &[0xAA]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0050, 0x00, &[0xBB]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.min_address(), Some(0x10));
        assert_eq!(file.max_address(), Some(0x51));
    }

    #[test]
    fn test_total_data_bytes() {
        let mut hex = make_line(0x0000, 0x00, &[0x01, 0x02]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0100, 0x00, &[0x03, 0x04, 0x05]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.total_data_bytes(), 5);
    }

    #[test]
    fn test_total_gap_bytes() {
        let mut hex = make_line(0x0000, 0x00, &[0x01, 0x02]);
        hex.push(b'\n');
        hex.extend_from_slice(&make_line(0x0008, 0x00, &[0x03]));
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.total_gap_bytes(), 6); // gap from 0x02 to 0x08
    }

    #[test]
    fn test_entry_point_from_start_lin_addr() {
        let mut hex = make_line(0x0000, 0x05, &[0x00, 0x00, 0x00, 0x40]);
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.entry_point(), Some(0x40));
    }

    #[test]
    fn test_entry_point_falls_back_to_first_region() {
        let mut hex = make_line(0x0200, 0x00, &[0xAA]);
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        assert_eq!(file.entry_point(), Some(0x200));
    }

    // ── encode / round-trip ───────────────────────────────────────────────────

    #[test]
    fn test_encode_and_parse_round_trip() {
        let original = vec![0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let encoded = encode_to_ihex(&original, 0x0800_0000, 4);
        let parsed = IhexFile::parse(encoded.as_bytes()).unwrap();
        let rebuilt = parsed.build_binary_image(Some(0x0800_0000), 0x00);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn test_encode_eof_present() {
        let encoded = encode_to_ihex(&[0xAAu8], 0x0000_0000, 16);
        assert!(encoded.contains(":00000001FF"));
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ihex_file_display() {
        let mut hex = make_line(0x0000, 0x00, &[0xDE, 0xAD]);
        hex.push(b'\n');
        hex.extend_from_slice(&eof_line());
        let file = IhexFile::parse(&hex).unwrap();
        let s = file.to_string();
        assert!(s.contains("regions=1"));
        assert!(s.contains("total_bytes=2"));
    }

    #[test]
    fn test_mem_region_display() {
        let r = MemRegion {
            start_addr: 0x1000,
            data: vec![0u8; 256],
        };
        let s = r.to_string();
        assert!(s.contains("0x00001000"));
        assert!(s.contains("256 bytes"));
    }

    #[test]
    fn test_ihex_record_display() {
        let rec = IhexRecord {
            byte_count: 4,
            address: 0x0100,
            record_type: IhexType::Data,
            data: vec![1, 2, 3, 4],
            checksum: 0xEB,
        };
        let s = rec.to_string();
        assert!(s.contains("DATA"));
        assert!(s.contains("addr=0x0100"));
    }
}
