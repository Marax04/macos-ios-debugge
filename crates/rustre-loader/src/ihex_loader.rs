// ihex_loader.rs — Intel HEX format loader for RustRE

// ─── RecordType ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordType {
    Data,
    EndOfFile,
    ExtendedSegmentAddr,
    StartSegmentAddr,
    ExtendedLinearAddr,
    StartLinearAddr,
}

impl RecordType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Data),
            1 => Some(Self::EndOfFile),
            2 => Some(Self::ExtendedSegmentAddr),
            3 => Some(Self::StartSegmentAddr),
            4 => Some(Self::ExtendedLinearAddr),
            5 => Some(Self::StartLinearAddr),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Data => 0,
            Self::EndOfFile => 1,
            Self::ExtendedSegmentAddr => 2,
            Self::StartSegmentAddr => 3,
            Self::ExtendedLinearAddr => 4,
            Self::StartLinearAddr => 5,
        }
    }
}

// ─── IhexRecord ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IhexRecord {
    pub record_type: RecordType,
    pub byte_count: u8,
    pub address: u16,
    pub data: Vec<u8>,
}

impl IhexRecord {
    #[must_use] 
    pub fn new(record_type: RecordType, address: u16, data: Vec<u8>) -> Self {
        // Intel HEX byte_count field is 8 bits; data longer than 255 bytes
        // would silently truncate here.  Saturate to 255 so callers can detect
        // the overflow rather than receiving a silently wrong record.
        let byte_count = u8::try_from(data.len().min(255)).unwrap_or(u8::MAX);
        Self { record_type, byte_count, address, data }
    }

    /// Compute checksum: two's complement of (`byte_count` + `addr_hi` + `addr_lo` + `record_type` + `data_bytes`).
    #[must_use] 
    pub fn checksum(&self) -> u8 {
        let mut sum: u32 = u32::from(self.byte_count);
        sum += u32::from(self.address >> 8);
        sum += u32::from(self.address & 0xFF);
        sum += u32::from(self.record_type.as_u8());
        for &b in &self.data {
            sum += u32::from(b);
        }
        ((!sum).wrapping_add(1) & 0xFF) as u8
    }

    #[must_use] 
    pub fn is_end(&self) -> bool {
        self.record_type == RecordType::EndOfFile
    }
}

// ─── Parser ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl ParseError {
    fn new(line: usize, msg: &str) -> Self {
        Self { line, message: msg.to_string() }
    }
}

/// Parse a single `:LLAAAATT[DD...]CC` line.
///
/// # Errors
/// Returns a `String` describing the parse failure.
pub fn parse_ihex_line(line: &str) -> Result<IhexRecord, String> {
    let line = line.trim();
    if !line.starts_with(':') {
        return Err(format!("Line does not start with ':': {line}"));
    }
    let hex = &line[1..];
    if hex.len() < 10 {
        return Err(format!("Line too short: {line}"));
    }
    if !hex.len().is_multiple_of(2) {
        return Err("Odd hex length".to_string());
    }

    let bytes: Result<Vec<u8>, _> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect();
    let bytes = bytes.map_err(|e| format!("Hex decode error: {e}"))?;

    if bytes.len() < 5 {
        return Err("Record too short".to_string());
    }

    let byte_count = bytes[0];
    let address = u16::from_be_bytes([bytes[1], bytes[2]]);
    let record_type_raw = bytes[3];
    let record_type = RecordType::from_u8(record_type_raw)
        .ok_or_else(|| format!("Unknown record type: {record_type_raw}"))?;

    let expected_data_len = byte_count as usize;
    let actual_data_end = 4 + expected_data_len;
    if actual_data_end + 1 > bytes.len() {
        return Err(format!("Not enough bytes: expected {expected_data_len} data + 1 checksum"));
    }

    let data = bytes[4..actual_data_end].to_vec();
    let checksum = bytes[actual_data_end];

    // Verify checksum: sum of all bytes (including checksum) should be 0 mod 256
    let sum: u32 = bytes[..=actual_data_end].iter().map(|&b| u32::from(b)).sum();
    if (sum & 0xFF) != 0 {
        return Err(format!("Checksum mismatch: computed sum 0x{:02X}, expected 0x00", sum & 0xFF));
    }
    let _ = checksum;

    Ok(IhexRecord {
        record_type,
        byte_count,
        address,
        data,
    })
}

/// Parse an entire IHEX file (text) into records.
///
/// # Errors
/// Returns a [`ParseError`] if any line fails to parse.
pub fn parse_ihex_file(text: &str) -> Result<Vec<IhexRecord>, ParseError> {
    let mut records = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let rec = parse_ihex_line(trimmed)
            .map_err(|e| ParseError::new(line_idx + 1, &e))?;
        let is_end = rec.is_end();
        records.push(rec);
        if is_end { break; }
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
        // Saturate rather than wrap: if base + len would exceed u32::MAX, return
        // u32::MAX so callers that compare against this value fail safely.
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

// ─── LoadedMemory ────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct LoadedMemory {
    pub segments: Vec<MemorySegment>,
    pub start_address: Option<u32>,
}

impl LoadedMemory {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Return all gaps between segments larger than `min_gap`.
    #[must_use] 
    pub fn find_gaps(&self) -> Vec<(u32, u32)> {
        if self.segments.len() < 2 { return vec![]; }
        let mut segs = self.segments.clone();
        segs.sort_by_key(|s| s.base);
        let mut gaps = Vec::new();
        for i in 1..segs.len() {
            let prev_end = segs[i-1].end();
            let cur_start = segs[i].base;
            if prev_end < cur_start {
                gaps.push((prev_end, cur_start));
            }
        }
        gaps
    }

    /// Merge adjacent segments whose gap is <= `threshold` bytes.
    ///
    /// The `threshold` is capped internally at 1 MiB to prevent a malformed
    /// file from causing unbounded heap growth when the caller passes an
    /// unreasonably large value derived from untrusted input.
    pub fn merge_adjacent_segments(&mut self, threshold: u32) {
        // Cap: never fill more than 1 MiB of padding between two segments.
        // A caller that truly needs larger gaps should process them explicitly.
        const MAX_PAD: u32 = 1024 * 1024;
        let threshold = threshold.min(MAX_PAD);
        if self.segments.len() < 2 { return; }
        self.segments.sort_by_key(|s| s.base);
        let mut merged: Vec<MemorySegment> = Vec::new();
        for seg in self.segments.drain(..) {
            if let Some(last) = merged.last_mut() {
                let gap = seg.base.saturating_sub(last.end());
                if gap <= threshold {
                    let pad = gap as usize;
                    last.data.extend(std::iter::repeat_n(0xFF, pad));
                    last.data.extend_from_slice(&seg.data);
                    continue;
                }
            }
            merged.push(seg);
        }
        self.segments = merged;
    }

    #[must_use] 
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|s| s.data.len()).sum()
    }
}

// ─── IhexLoader ───────────────────────────────────────────────────────────────

pub struct IhexLoader;

impl IhexLoader {
    #[must_use] 
    pub const fn new() -> Self { Self }

    /// Load IHEX records into memory segments (handles extended linear addr).
    #[must_use] 
    pub fn load_from_records(&self, records: &[IhexRecord]) -> LoadedMemory {
        let mut memory = LoadedMemory::new();
        let mut upper: u32 = 0; // Upper 16 bits for extended linear addressing

        for rec in records {
            match &rec.record_type {
                RecordType::Data => {
                    let full_addr: u32 = upper | u32::from(rec.address);
                    Self::write_to_memory(&mut memory, full_addr, &rec.data);
                }
                RecordType::ExtendedLinearAddr => {
                    if rec.data.len() >= 2 {
                        upper = u32::from(u16::from_be_bytes([rec.data[0], rec.data[1]])) << 16;
                    }
                }
                RecordType::ExtendedSegmentAddr => {
                    if rec.data.len() >= 2 {
                        let seg = u32::from(u16::from_be_bytes([rec.data[0], rec.data[1]]));
                        upper = seg << 4;
                    }
                }
                RecordType::StartLinearAddr => {
                    if rec.data.len() >= 4 {
                        let addr = u32::from_be_bytes([rec.data[0], rec.data[1], rec.data[2], rec.data[3]]);
                        memory.start_address = Some(addr);
                    }
                }
                RecordType::StartSegmentAddr => {
                    if rec.data.len() >= 4 {
                        let cs = u32::from(u16::from_be_bytes([rec.data[0], rec.data[1]]));
                        let ip = u32::from(u16::from_be_bytes([rec.data[2], rec.data[3]]));
                        memory.start_address = Some((cs << 4) + ip);
                    }
                }
                RecordType::EndOfFile => break,
            }
        }
        memory
    }

    fn write_to_memory(memory: &mut LoadedMemory, addr: u32, data: &[u8]) {
        // Find a segment that can be appended to
        for seg in &mut memory.segments {
            if seg.end() == addr {
                seg.data.extend_from_slice(data);
                return;
            }
        }
        // Create a new segment
        let mut seg = MemorySegment::new(addr);
        seg.data.extend_from_slice(data);
        memory.segments.push(seg);
    }

    /// Parse and load IHEX text.
    ///
    /// # Errors
    /// Returns a [`ParseError`] if parsing fails.
    pub fn load_str(&self, text: &str) -> Result<LoadedMemory, ParseError> {
        let records = parse_ihex_file(text)?;
        Ok(self.load_from_records(&records))
    }

    /// Serialize loaded memory back to IHEX format.
    #[must_use] 
    pub fn serialize_to_ihex(&self, memory: &LoadedMemory) -> String {
        let mut lines = Vec::new();
        let mut segs = memory.segments.clone();
        segs.sort_by_key(|s| s.base);

        let mut current_upper: u32 = 0;

        for seg in &segs {
            let mut offset: usize = 0;
            while offset < seg.data.len() {
                let addr = seg.base + u32::try_from(offset).unwrap_or(u32::MAX);
                let upper = addr >> 16;

                // Emit extended linear address record if upper word changed
                if upper != current_upper {
                    current_upper = upper;
                    let ela_data = vec![(upper >> 8) as u8, (upper & 0xFF) as u8];
                    let ela_rec = IhexRecord::new(RecordType::ExtendedLinearAddr, 0, ela_data);
                    lines.push(format_record(&ela_rec));
                }

                let low_addr = (addr & 0xFFFF) as u16;
                let chunk_len = 16.min(seg.data.len() - offset);
                let chunk = seg.data[offset..offset + chunk_len].to_vec();
                let rec = IhexRecord::new(RecordType::Data, low_addr, chunk);
                lines.push(format_record(&rec));
                offset += chunk_len;
            }
        }

        // End of file record
        let eof = IhexRecord::new(RecordType::EndOfFile, 0, vec![]);
        lines.push(format_record(&eof));

        // Emit start address if known
        if let Some(start) = memory.start_address {
            let data = vec![(start >> 24) as u8, ((start >> 16) & 0xFF) as u8,
                            ((start >> 8) & 0xFF) as u8, (start & 0xFF) as u8];
            let sla = IhexRecord::new(RecordType::StartLinearAddr, 0, data);
            lines.insert(0, format_record(&sla));
        }

        lines.join("\n")
    }
}

fn format_record(rec: &IhexRecord) -> String {
    use std::fmt::Write as _;
    let mut bytes = vec![rec.byte_count, (rec.address >> 8) as u8, (rec.address & 0xFF) as u8, rec.record_type.as_u8()];
    bytes.extend_from_slice(&rec.data);
    let checksum = rec.checksum();
    bytes.push(checksum);
    let hex: String = bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| { let _ = write!(acc, "{b:02X}"); acc });
    format!(":{hex}")
}

impl Default for IhexLoader {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_IHEX: &str = ":10010000214601360121470136007EFE09D2190140\n:00000001FF\n";

    #[test]
    fn test_record_type_roundtrip() {
        for v in 0u8..=5 {
            let rt = RecordType::from_u8(v).unwrap();
            assert_eq!(rt.as_u8(), v);
        }
    }

    #[test]
    fn test_record_type_unknown() {
        assert!(RecordType::from_u8(6).is_none());
    }

    #[test]
    fn test_parse_ihex_line_data() {
        let rec = parse_ihex_line(":10010000214601360121470136007EFE09D2190140").unwrap();
        assert_eq!(rec.record_type, RecordType::Data);
        assert_eq!(rec.byte_count, 16);
        assert_eq!(rec.address, 0x0100);
        assert_eq!(rec.data.len(), 16);
    }

    #[test]
    fn test_parse_ihex_line_eof() {
        let rec = parse_ihex_line(":00000001FF").unwrap();
        assert_eq!(rec.record_type, RecordType::EndOfFile);
        assert!(rec.is_end());
    }

    #[test]
    fn test_parse_ihex_line_bad_checksum() {
        let result = parse_ihex_line(":10010000214601360121470136007EFE09D2190141");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ihex_line_no_colon() {
        let result = parse_ihex_line("10010000214601360121470136007EFE09D2190140");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ihex_file_simple() {
        let records = parse_ihex_file(SIMPLE_IHEX).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type, RecordType::Data);
        assert_eq!(records[1].record_type, RecordType::EndOfFile);
    }

    #[test]
    fn test_ihex_loader_load_str() {
        let loader = IhexLoader::new();
        let mem = loader.load_str(SIMPLE_IHEX).unwrap();
        assert_eq!(mem.segments.len(), 1);
        assert_eq!(mem.segments[0].base, 0x0100);
        assert_eq!(mem.total_bytes(), 16);
    }

    #[test]
    fn test_extended_linear_addr() {
        // Extended linear address sets upper 16 bits
        // ELA upper=0x0004: bc=02,addr=0,type=04,data=00 04; cs = -(2+4+0+4)=0xF6
        // Data line: bc=10,addr=0,type=0,data=0..0F (sum=0x78); cs = -(0x10+0x78)=0x78
        // ELA upper=0x0004: bc=02,addr=0,type=04,data=00 04; cs = -(2+4+0+4)=0xF6
        // Data line: bc=10,addr=0,type=0,data=0..0F (sum=0x78); cs = -(0x10+0x78)=0x78
        let text = ":020000040004F6\n:10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n";
        let loader = IhexLoader::new();
        let mem = loader.load_str(text).unwrap();
        // Base should be 0x00040000 + 0x0000 = 0x00040000
        assert_eq!(mem.segments[0].base, 0x0004_0000);
    }

    #[test]
    fn test_find_gaps() {
        let mut mem = LoadedMemory::new();
        let mut s1 = MemorySegment::new(0x0000);
        s1.data = vec![1; 16];
        let mut s2 = MemorySegment::new(0x0100);
        s2.data = vec![2; 16];
        mem.segments = vec![s1, s2];
        let gaps = mem.find_gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], (0x0010, 0x0100));
    }

    #[test]
    fn test_merge_adjacent_segments() {
        let mut mem = LoadedMemory::new();
        let mut s1 = MemorySegment::new(0x0000);
        s1.data = vec![1; 4];
        let mut s2 = MemorySegment::new(0x0008); // 4-byte gap
        s2.data = vec![2; 4];
        mem.segments = vec![s1, s2];
        mem.merge_adjacent_segments(4);
        assert_eq!(mem.segments.len(), 1);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let loader = IhexLoader::new();
        let mem = loader.load_str(SIMPLE_IHEX).unwrap();
        let output = loader.serialize_to_ihex(&mem);
        assert!(output.contains(":10"));
        assert!(output.contains(":00000001FF"));
    }

    #[test]
    fn test_checksum_valid() {
        let rec = IhexRecord::new(RecordType::Data, 0x0100, vec![0x21, 0x46, 0x01, 0x36]);
        let cs = rec.checksum();
        // Verify that sum of all bytes + checksum = 0 mod 256
        let total: u32 = (u32::from(rec.byte_count) + 0x01) + rec.data.iter().map(|&b| u32::from(b)).sum::<u32>() + u32::from(cs);
        assert_eq!(total & 0xFF, 0);
    }

    #[test]
    fn test_memory_segment_contains() {
        let mut seg = MemorySegment::new(0x1000);
        seg.data = vec![0xFF; 16];
        assert!(seg.contains(0x1000));
        assert!(seg.contains(0x100F));
        assert!(!seg.contains(0x1010));
    }

    #[test]
    fn test_parse_empty_file() {
        let records = parse_ihex_file("").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_start_linear_address() {
        // SLA addr=0x00003800: bc=04,type=05,data=00 00 38 00; cs = -(4+5+0x38)=0xBF
        let text = ":0400000500003800BF\n:00000001FF\n";
        let loader = IhexLoader::new();
        let mem = loader.load_str(text).unwrap();
        assert_eq!(mem.start_address, Some(0x0000_3800));
    }
}
