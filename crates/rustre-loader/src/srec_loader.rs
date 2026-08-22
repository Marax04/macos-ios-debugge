// srec_loader.rs — Motorola S-record loader for RustRE

// ─── SrecType ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrecType {
    S0Header,
    S1Data16,
    S2Data24,
    S3Data32,
    S5Count16,
    S7Start32,
    S8Start24,
    S9Start16,
}

impl SrecType {
    #[must_use] 
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            '0' => Some(Self::S0Header),
            '1' => Some(Self::S1Data16),
            '2' => Some(Self::S2Data24),
            '3' => Some(Self::S3Data32),
            '5' => Some(Self::S5Count16),
            '7' => Some(Self::S7Start32),
            '8' => Some(Self::S8Start24),
            '9' => Some(Self::S9Start16),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn as_char(&self) -> char {
        match self {
            Self::S0Header => '0',
            Self::S1Data16 => '1',
            Self::S2Data24 => '2',
            Self::S3Data32 => '3',
            Self::S5Count16 => '5',
            Self::S7Start32 => '7',
            Self::S8Start24 => '8',
            Self::S9Start16 => '9',
        }
    }

    /// Number of address bytes for this record type.
    #[must_use] 
    pub const fn addr_bytes(&self) -> usize {
        match self {
            Self::S0Header | Self::S1Data16 | Self::S9Start16 | Self::S5Count16 => 2,
            Self::S2Data24 | Self::S8Start24 => 3,
            Self::S3Data32 | Self::S7Start32 => 4,
        }
    }

    #[must_use] 
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::S1Data16 | Self::S2Data24 | Self::S3Data32)
    }

    #[must_use] 
    pub const fn is_start(&self) -> bool {
        matches!(self, Self::S7Start32 | Self::S8Start24 | Self::S9Start16)
    }

    #[must_use] 
    pub fn is_header(&self) -> bool {
        *self == Self::S0Header
    }
}

// ─── SrecRecord ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrecRecord {
    pub type_: SrecType,
    pub address: u32,
    pub data: Vec<u8>,
}

impl SrecRecord {
    #[must_use] 
    pub const fn new(type_: SrecType, address: u32, data: Vec<u8>) -> Self {
        Self { type_, address, data }
    }

    /// Compute byte count = `addr_bytes` + `data_bytes` + 1 (checksum).
    #[must_use] 
    pub fn byte_count(&self) -> u8 {
        // The S-record byte count field is 8 bits.  Saturate to 0xFF to avoid
        // silent truncation when data is unusually long; the serialiser will
        // produce an invalid record in that case, which is far easier to debug
        // than a silently corrupt checksum.
        u8::try_from((self.type_.addr_bytes() + self.data.len() + 1).min(0xFF)).unwrap_or(u8::MAX)
    }

    /// Compute S-record checksum: 0xFF - (`sum_of_all_bytes` & 0xFF).
    #[must_use] 
    pub fn checksum(&self) -> u8 {
        let bc = u32::from(self.byte_count());
        let addr_bytes = self.type_.addr_bytes();
        let mut sum: u32 = bc;
        // Add address bytes (big-endian, only as many as addr_bytes)
        for i in (0..addr_bytes).rev() {
            sum += (self.address >> (i * 8)) & 0xFF;
        }
        for &b in &self.data {
            sum += u32::from(b);
        }
        u8::try_from(0xFF_u32 - (sum & 0xFF)).unwrap_or(u8::MAX)
    }
}

// ─── Parser ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SrecParseError {
    pub line: usize,
    pub message: String,
}

impl SrecParseError {
    fn new(line: usize, msg: &str) -> Self {
        Self { line, message: msg.to_string() }
    }
}

/// Parse a single Sxx… line.
///
/// # Errors
/// Returns a `String` describing the parse failure.
pub fn parse_srec_line(line: &str) -> Result<SrecRecord, String> {
    let line = line.trim();
    if line.len() < 2 {
        return Err("Line too short".to_string());
    }
    if !line.starts_with('S') {
        return Err(format!("Line does not start with 'S': {line}"));
    }
    let type_char = line.chars().nth(1).ok_or("Missing type character")?;
    let type_ = SrecType::from_char(type_char)
        .ok_or_else(|| format!("Unknown record type: S{type_char}"))?;

    let hex = &line[2..];
    if hex.len() < 2 || !hex.len().is_multiple_of(2) {
        return Err("Hex data has odd length or is too short".to_string());
    }

    let bytes: Result<Vec<u8>, _> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect();
    let bytes = bytes.map_err(|e| format!("Hex decode error: {e}"))?;

    if bytes.is_empty() {
        return Err("Empty record".to_string());
    }

    let byte_count = bytes[0] as usize;
    if byte_count + 1 > bytes.len() {
        return Err(format!("Byte count {} exceeds available bytes {}", byte_count, bytes.len() - 1));
    }

    let addr_bytes = type_.addr_bytes();
    if byte_count < addr_bytes + 1 {
        return Err(format!("Byte count {byte_count} too small for address ({addr_bytes} bytes) + checksum"));
    }

    // Verify checksum: sum of byte_count .. last_data_byte + checksum_byte = 0xFF
    let payload = &bytes[0..=byte_count];
    let sum: u32 = payload[..payload.len() - 1].iter().map(|&b| u32::from(b)).sum();
    let expected_checksum = u8::try_from(0xFF_u32 - (sum & 0xFF)).unwrap_or(u8::MAX);
    let actual_checksum = payload[payload.len() - 1];
    if actual_checksum != expected_checksum {
        return Err(format!("Checksum mismatch: got 0x{actual_checksum:02X}, expected 0x{expected_checksum:02X}"));
    }

    // Decode address
    let mut address: u32 = 0;
    for i in 0..addr_bytes {
        address = (address << 8) | u32::from(bytes[1 + i]);
    }

    let data_start = 1 + addr_bytes;
    let data_end = byte_count; // before checksum
    let data = if data_end > data_start {
        bytes[data_start..data_end].to_vec()
    } else {
        vec![]
    };

    Ok(SrecRecord { type_, address, data })
}

/// Parse an entire SREC file.
///
/// # Errors
/// Returns a [`SrecParseError`] if any line fails to parse.
pub fn parse_srec_file(text: &str) -> Result<Vec<SrecRecord>, SrecParseError> {
    let mut records = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let rec = parse_srec_line(trimmed)
            .map_err(|e| SrecParseError::new(line_idx + 1, &e))?;
        records.push(rec);
    }
    Ok(records)
}

// ─── MemorySegment ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemorySegment {
    pub base: u32,
    pub data: Vec<u8>,
}

impl MemorySegment {
    #[must_use] 
    pub const fn new(base: u32) -> Self {
        Self { base, data: Vec::new() }
    }

    #[must_use]
    pub fn end(&self) -> u32 {
        // Use saturating_add so that a crafted base + huge data.len() cannot
        // wrap around and produce a spurious address-match in write_to_memory.
        self.base.saturating_add(u32::try_from(self.data.len()).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub fn contains(&self, addr: u32) -> bool {
        addr >= self.base && addr < self.end()
    }

    #[must_use] 
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        let off = addr.checked_sub(self.base)? as usize;
        self.data.get(off).copied()
    }
}

// ─── SrecMemory ───────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SrecMemory {
    pub segments: Vec<MemorySegment>,
    entry_point: Option<u32>,
    header_info: Option<String>,
}

impl SrecMemory {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use] 
    pub const fn entry_point(&self) -> Option<u32> {
        self.entry_point
    }

    #[must_use] 
    pub fn get_header_info(&self) -> Option<&str> {
        self.header_info.as_deref()
    }

    #[must_use] 
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|s| s.data.len()).sum()
    }

    #[must_use] 
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        for seg in &self.segments {
            if let Some(b) = seg.read_u8(addr) {
                return Some(b);
            }
        }
        None
    }
}

// ─── SrecLoader ───────────────────────────────────────────────────────────────

pub struct SrecLoader;

impl SrecLoader {
    #[must_use] 
    pub const fn new() -> Self { Self }

    #[must_use] 
    pub fn load_from_records(&self, records: &[SrecRecord]) -> SrecMemory {
        let mut mem = SrecMemory::new();
        for rec in records {
            match &rec.type_ {
                SrecType::S0Header => {
                    // Header data is typically module name / comment
                    let s = String::from_utf8_lossy(&rec.data).to_string();
                    mem.header_info = Some(s);
                }
                SrecType::S1Data16 | SrecType::S2Data24 | SrecType::S3Data32 => {
                    Self::write_to_memory(&mut mem, rec.address, &rec.data);
                }
                SrecType::S7Start32 | SrecType::S8Start24 | SrecType::S9Start16 => {
                    mem.entry_point = Some(rec.address);
                }
                SrecType::S5Count16 => {
                    // Record count; ignore for loading
                }
            }
        }
        mem
    }

    fn write_to_memory(mem: &mut SrecMemory, addr: u32, data: &[u8]) {
        for seg in &mut mem.segments {
            if seg.end() == addr {
                seg.data.extend_from_slice(data);
                return;
            }
        }
        let mut seg = MemorySegment::new(addr);
        seg.data.extend_from_slice(data);
        mem.segments.push(seg);
    }

    /// # Errors
    /// Returns a [`SrecParseError`] if parsing fails.
    pub fn load_str(&self, text: &str) -> Result<SrecMemory, SrecParseError> {
        let records = parse_srec_file(text)?;
        Ok(self.load_from_records(&records))
    }

    /// Serialize memory back to S-record format.
    /// `addr_size` = 2 (S1), 3 (S2), or 4 (S3)
    #[must_use] 
    pub fn serialize_to_srec(&self, mem: &SrecMemory, addr_size: u8) -> String {
        let data_type = match addr_size {
            2 => SrecType::S1Data16,
            3 => SrecType::S2Data24,
            _ => SrecType::S3Data32,
        };
        let term_type = match addr_size {
            2 => SrecType::S9Start16,
            3 => SrecType::S8Start24,
            _ => SrecType::S7Start32,
        };
        let mut lines = Vec::new();

        // S0 header
        let header_data: Vec<u8> = mem.header_info.as_deref().unwrap_or("RustRE").bytes().collect();
        let s0 = SrecRecord::new(SrecType::S0Header, 0, header_data);
        lines.push(format_srec_record(&s0));

        // Data records
        let mut segs = mem.segments.clone();
        segs.sort_by_key(|s| s.base);
        let mut total_records = 0u16;
        for seg in &segs {
            let mut offset = 0;
            while offset < seg.data.len() {
                let chunk_len = 32.min(seg.data.len() - offset);
                let addr = seg.base + u32::try_from(offset).unwrap_or(u32::MAX);
                let chunk = seg.data[offset..offset + chunk_len].to_vec();
                let rec = SrecRecord::new(data_type.clone(), addr, chunk);
                lines.push(format_srec_record(&rec));
                offset += chunk_len;
                total_records += 1;
            }
        }

        // S5 record count
        let s5 = SrecRecord::new(SrecType::S5Count16, u32::from(total_records), vec![]);
        lines.push(format_srec_record(&s5));

        // Termination record
        let ep = mem.entry_point().unwrap_or_else(|| mem.segments.first().map_or(0, |s| s.base));
        let term = SrecRecord::new(term_type, ep, vec![]);
        lines.push(format_srec_record(&term));

        lines.join("\n")
    }
}

fn format_srec_record(rec: &SrecRecord) -> String {
    use std::fmt::Write as _;
    let addr_bytes = rec.type_.addr_bytes();
    let bc = u8::try_from((addr_bytes + rec.data.len() + 1).min(0xFF)).unwrap_or(u8::MAX);
    let mut bytes = vec![bc];
    for i in (0..addr_bytes).rev() {
        bytes.push(((rec.address >> (i * 8)) & 0xFF) as u8);
    }
    bytes.extend_from_slice(&rec.data);
    let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
    let checksum = u8::try_from(0xFF_u32 - (sum & 0xFF)).unwrap_or(u8::MAX);
    bytes.push(checksum);
    let hex: String = bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| { let _ = write!(acc, "{b:02X}"); acc });
    format!("S{}{}", rec.type_.as_char(), hex)
}

impl Default for SrecLoader {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Valid S1 record: S1 0B 0000 0102030405060708090A B1
    // Valid S1 record: bc=0x0B, addr=0x0000, data=01..08, cs = 0xFF - (0x0B+0+0+1+2+3+4+5+6+7+8)&0xFF = 0xD0
    const SREC_S1: &str = "S10B00000102030405060708D0\nS9030000FC\n";
    // S3 data record + S7 terminator; cs = 0xFF - (9+0+0x12+0x34+0x56+1+2+3+4)&0xFF = 0x50
    const SREC_S3: &str = "S309001234560102030450\nS70500000000FA\n";

    #[test]
    fn test_srectype_roundtrip() {
        for c in &['0', '1', '2', '3', '5', '7', '8', '9'] {
            let t = SrecType::from_char(*c).unwrap();
            assert_eq!(t.as_char(), *c);
        }
    }

    #[test]
    fn test_srectype_unknown() {
        assert!(SrecType::from_char('4').is_none());
    }

    #[test]
    fn test_parse_srec_s1_basic() {
        let rec = parse_srec_line("S10B00000102030405060708D0").unwrap();
        assert_eq!(rec.type_, SrecType::S1Data16);
        assert_eq!(rec.address, 0x0000);
        assert_eq!(rec.data.len(), 8);
    }

    #[test]
    fn test_parse_srec_s9_terminator() {
        let rec = parse_srec_line("S9030000FC").unwrap();
        assert_eq!(rec.type_, SrecType::S9Start16);
        assert_eq!(rec.address, 0x0000);
        assert!(rec.data.is_empty());
    }

    #[test]
    fn test_parse_srec_s3_32bit_addr() {
        let rec = parse_srec_line("S309001234560102030450").unwrap();
        assert_eq!(rec.type_, SrecType::S3Data32);
        assert_eq!(rec.address, 0x0012_3456);
        assert_eq!(rec.data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_srec_bad_checksum() {
        // Modify last byte of checksum
        // Same as SREC_S1 but with last byte (cs) corrupted from 0xD0 -> 0xBF
        let result = parse_srec_line("S10B00000102030405060708BF");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_srec_file_s1() {
        let recs = parse_srec_file(SREC_S1).unwrap();
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn test_load_from_records_s1() {
        let loader = SrecLoader::new();
        let mem = loader.load_str(SREC_S1).unwrap();
        assert_eq!(mem.segments.len(), 1);
        assert_eq!(mem.segments[0].base, 0x0000);
        assert_eq!(mem.total_bytes(), 8);
    }

    #[test]
    fn test_load_from_records_s3() {
        let loader = SrecLoader::new();
        let mem = loader.load_str(SREC_S3).unwrap();
        assert_eq!(mem.segments[0].base, 0x0012_3456);
        assert_eq!(mem.entry_point(), Some(0x0000_0000));
    }

    #[test]
    fn test_entry_point_s7() {
        // S7 with address 0x00ABCDEF
        let loader = SrecLoader::new();
        // Parse records directly to avoid checksum issues in test data
        let recs = vec![
            SrecRecord::new(SrecType::S3Data32, 0x1234_5678, vec![0x00]),
            SrecRecord::new(SrecType::S7Start32, 0x00AB_CDEF, vec![]),
        ];
        let mem = loader.load_from_records(&recs);
        assert_eq!(mem.entry_point(), Some(0x00AB_CDEF));
    }

    #[test]
    fn test_s0_header_stored() {
        let recs = vec![
            SrecRecord::new(SrecType::S0Header, 0, b"MyModule".to_vec()),
            SrecRecord::new(SrecType::S9Start16, 0, vec![]),
        ];
        let loader = SrecLoader::new();
        let mem = loader.load_from_records(&recs);
        assert_eq!(mem.get_header_info(), Some("MyModule"));
    }

    #[test]
    fn test_checksum_valid_s1() {
        let rec = SrecRecord::new(SrecType::S1Data16, 0x0000, vec![0x01, 0x02, 0x03]);
        let cs = rec.checksum();
        // Manually verify: byte_count = 2 + 3 + 1 = 6; sum = 6+0+0+1+2+3 = 12; cs = 0xFF-0x0C = 0xF3
        let bc = rec.byte_count();
        let sum: u32 = u32::from(bc) + 0x01 + 0x02 + 0x03;
        assert_eq!(cs, (0xFF - (sum & 0xFF)) as u8);
    }

    #[test]
    fn test_serialize_and_reparse() {
        let loader = SrecLoader::new();
        let mut mem = SrecMemory::new();
        let mut seg = MemorySegment::new(0x1000);
        seg.data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        mem.segments.push(seg);
        let text = loader.serialize_to_srec(&mem, 2);
        assert!(text.contains("S1"));
        // Re-parse
        let mem2 = loader.load_str(&text).unwrap();
        assert!(mem2.total_bytes() >= 4);
    }

    #[test]
    fn test_read_u8_from_memory() {
        let recs = vec![SrecRecord::new(SrecType::S1Data16, 0x1000, vec![0xAB, 0xCD])];
        let loader = SrecLoader::new();
        let mem = loader.load_from_records(&recs);
        assert_eq!(mem.read_u8(0x1000), Some(0xAB));
        assert_eq!(mem.read_u8(0x1001), Some(0xCD));
        assert_eq!(mem.read_u8(0x1002), None);
    }

    #[test]
    fn test_addr_bytes_s2() {
        assert_eq!(SrecType::S2Data24.addr_bytes(), 3);
    }

    #[test]
    fn test_is_data_types() {
        assert!(SrecType::S1Data16.is_data());
        assert!(SrecType::S2Data24.is_data());
        assert!(SrecType::S3Data32.is_data());
        assert!(!SrecType::S0Header.is_data());
    }

    #[test]
    fn test_is_start_types() {
        assert!(SrecType::S7Start32.is_start());
        assert!(SrecType::S9Start16.is_start());
        assert!(!SrecType::S1Data16.is_start());
    }
}
