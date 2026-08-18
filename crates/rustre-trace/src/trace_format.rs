// trace_format.rs — Unified trace format serialization and deserialization
//
// Supports reading and writing execution traces from:
//   - Custom binary format (RustRE native)
//   - DynamoRIO/drcov coverage format (basic-block coverage logs)
//   - Frida GumStalker JSON format
//   - Intel PT (Processor Trace) packet stream (simplified decode)
//   - Simple CSV trace (address, event_type)
//
// All formats are normalized into TraceRecord sequences.

use std::io::{self, Write};
use std::fmt;

// ── Trace event types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TraceEventKind {
    Instruction = 0x01,
    MemRead = 0x02,
    MemWrite = 0x03,
    Call = 0x04,
    Return = 0x05,
    Branch = 0x06,
    Syscall = 0x07,
    Exception = 0x08,
    BasicBlock = 0x09,
    ModuleLoad = 0x0A,
    ThreadCreate = 0x0B,
    ThreadExit = 0x0C,
    RegChange = 0x0D,
    Unknown = 0xFF,
}

impl TraceEventKind {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Instruction, 0x02 => Self::MemRead, 0x03 => Self::MemWrite,
            0x04 => Self::Call, 0x05 => Self::Return, 0x06 => Self::Branch,
            0x07 => Self::Syscall, 0x08 => Self::Exception, 0x09 => Self::BasicBlock,
            0x0A => Self::ModuleLoad, 0x0B => Self::ThreadCreate, 0x0C => Self::ThreadExit,
            0x0D => Self::RegChange, _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Instruction => "insn", Self::MemRead => "mem_read", Self::MemWrite => "mem_write",
            Self::Call => "call", Self::Return => "ret", Self::Branch => "branch",
            Self::Syscall => "syscall", Self::Exception => "exception",
            Self::BasicBlock => "bb", Self::ModuleLoad => "module_load",
            Self::ThreadCreate => "thread_create", Self::ThreadExit => "thread_exit",
            Self::RegChange => "reg_change", Self::Unknown => "unknown",
        }
    }
}

// ── Normalized trace record ────────────────────────────────────────────────────

/// A single normalized trace event
#[derive(Debug, Clone)]
pub struct TraceRecord {
    /// Sequence number (0-based; may be approximate for some formats)
    pub seq: u64,
    /// Thread ID
    pub tid: u32,
    /// Program counter at the time of the event
    pub pc: u64,
    pub event: TraceEventKind,
    /// Auxiliary value (target address for calls/branches, syscall number, etc.)
    pub aux: u64,
    /// Memory address (for mem read/write)
    pub mem_addr: u64,
    /// Operand size in bytes (for mem read/write)
    pub mem_size: u8,
    /// Raw instruction bytes (may be empty)
    pub insn_bytes: Vec<u8>,
}

impl TraceRecord {
    #[must_use]
    pub const fn new_insn(seq: u64, tid: u32, pc: u64) -> Self {
        TraceRecord { seq, tid, pc, event: TraceEventKind::Instruction,
            aux: 0, mem_addr: 0, mem_size: 0, insn_bytes: vec![] }
    }

    #[must_use]
    pub const fn new_call(seq: u64, tid: u32, pc: u64, target: u64) -> Self {
        TraceRecord { seq, tid, pc, event: TraceEventKind::Call,
            aux: target, mem_addr: 0, mem_size: 0, insn_bytes: vec![] }
    }

    #[must_use]
    pub const fn new_bb(seq: u64, tid: u32, pc: u64, size: u32) -> Self {
        TraceRecord { seq, tid, pc, event: TraceEventKind::BasicBlock,
            aux: size as u64, mem_addr: 0, mem_size: 0, insn_bytes: vec![] }
    }

    #[must_use]
    pub const fn new_mem(seq: u64, tid: u32, pc: u64, is_write: bool, addr: u64, size: u8) -> Self {
        let event = if is_write { TraceEventKind::MemWrite } else { TraceEventKind::MemRead };
        TraceRecord { seq, tid, pc, event, aux: 0, mem_addr: addr, mem_size: size, insn_bytes: vec![] }
    }
}

// ── Format error ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TraceFormatError {
    Io(io::Error),
    BadMagic([u8; 4]),
    UnsupportedVersion(u32),
    Truncated,
    ParseError(String),
    JsonError(String),
}

impl fmt::Display for TraceFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceFormatError::Io(e) => write!(f, "IO error: {e}"),
            TraceFormatError::BadMagic(m) => write!(f, "Bad magic: {m:02X?}"),
            TraceFormatError::UnsupportedVersion(v) => write!(f, "Unsupported version: {v}"),
            TraceFormatError::Truncated => write!(f, "Truncated trace"),
            TraceFormatError::ParseError(s) => write!(f, "Parse error: {s}"),
            TraceFormatError::JsonError(s) => write!(f, "JSON error: {s}"),
        }
    }
}

impl std::error::Error for TraceFormatError {}
impl From<io::Error> for TraceFormatError { fn from(e: io::Error) -> Self { TraceFormatError::Io(e) } }

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE BINARY FORMAT
// ═══════════════════════════════════════════════════════════════════════════════

pub const NATIVE_MAGIC: [u8; 4] = *b"RTRC";
pub const NATIVE_VERSION: u32 = 2;

/// Native binary trace file header (32 bytes)
#[derive(Debug, Clone)]
pub struct NativeTraceHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub flags: u32,
    pub record_count: u64,
    pub pid: u32,
    /// Target architecture (0=x86, `1=x86_64`, 2=arm, 3=arm64)
    pub arch: u8,
    pub _padding: [u8; 3],
    pub start_timestamp_ns: u64,
}

impl NativeTraceHeader {
    pub const SIZE: usize = 40;

    #[must_use]
    pub const fn new(record_count: u64, pid: u32, arch: u8) -> Self {
        NativeTraceHeader {
            magic: NATIVE_MAGIC,
            version: NATIVE_VERSION,
            flags: 0,
            record_count,
            pid,
            arch,
            _padding: [0; 3],
            start_timestamp_ns: 0,
        }
    }

    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::SIZE);
        v.extend_from_slice(&self.magic);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.flags.to_le_bytes());
        v.extend_from_slice(&self.record_count.to_le_bytes());
        v.extend_from_slice(&self.pid.to_le_bytes());
        v.push(self.arch);
        v.extend_from_slice(&self._padding);
        v.extend_from_slice(&self.start_timestamp_ns.to_le_bytes());
        // Trailing reserved word so the on-disk header is 8-byte aligned at
        // the announced SIZE (40 bytes).
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    }

    pub fn parse(data: &[u8]) -> Result<Self, TraceFormatError> {
        if data.len() < Self::SIZE { return Err(TraceFormatError::Truncated); }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        if magic != NATIVE_MAGIC { return Err(TraceFormatError::BadMagic(magic)); }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version > NATIVE_VERSION { return Err(TraceFormatError::UnsupportedVersion(version)); }
        Ok(NativeTraceHeader {
            magic,
            version,
            flags: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            record_count: u64::from_le_bytes([data[12],data[13],data[14],data[15],data[16],data[17],data[18],data[19]]),
            pid: u32::from_le_bytes([data[20],data[21],data[22],data[23]]),
            arch: data[24],
            _padding: [data[25], data[26], data[27]],
            start_timestamp_ns: u64::from_le_bytes([data[28],data[29],data[30],data[31],data[32],data[33],data[34],data[35]]),
        })
    }
}

/// Serialize a single `TraceRecord` into native binary (24 bytes fixed)
pub fn serialize_record(rec: &TraceRecord, out: &mut Vec<u8>) {
    out.extend_from_slice(&rec.seq.to_le_bytes());
    out.extend_from_slice(&rec.pc.to_le_bytes());
    out.extend_from_slice(&rec.aux.to_le_bytes());
    out.extend_from_slice(&rec.mem_addr.to_le_bytes());
    out.extend_from_slice(&rec.tid.to_le_bytes());
    out.push(rec.event as u8);
    out.push(rec.mem_size);
    // 11-byte instruction block (length-prefixed) preceded by one reserved
    // byte so the total record size is exactly 51 bytes.
    let max_insn = 11usize;
    let insn_len = rec.insn_bytes.len().min(max_insn) as u8;
    out.push(insn_len);
    out.push(0); // reserved
    out.extend_from_slice(&rec.insn_bytes[..insn_len as usize]);
    for _ in (insn_len as usize)..max_insn { out.push(0); }
}

/// Deserialize one `TraceRecord` from 51 bytes of native format
#[must_use]
pub fn deserialize_record(data: &[u8], offset: usize) -> Option<TraceRecord> {
    const REC_SIZE: usize = 51;
    if offset + REC_SIZE > data.len() { return None; }
    let d = &data[offset..];
    let seq = u64::from_le_bytes([d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7]]);
    let pc = u64::from_le_bytes([d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15]]);
    let aux = u64::from_le_bytes([d[16],d[17],d[18],d[19],d[20],d[21],d[22],d[23]]);
    let mem_addr = u64::from_le_bytes([d[24],d[25],d[26],d[27],d[28],d[29],d[30],d[31]]);
    let tid = u32::from_le_bytes([d[32],d[33],d[34],d[35]]);
    let event = TraceEventKind::from_u8(d[36]);
    let mem_size = d[37];
    let insn_len = d[38] as usize;
    let insn_bytes = d[40..40 + insn_len.min(15)].to_vec();
    Some(TraceRecord { seq, tid, pc, event, aux, mem_addr, mem_size, insn_bytes })
}

/// Write a full native trace file to a writer
pub fn write_native_trace<W: Write>(
    writer: &mut W,
    records: &[TraceRecord],
    pid: u32,
    arch: u8,
) -> Result<(), TraceFormatError> {
    let hdr = NativeTraceHeader::new(records.len() as u64, pid, arch);
    writer.write_all(&hdr.serialize())?;
    let mut buf = Vec::with_capacity(64);
    for rec in records {
        buf.clear();
        serialize_record(rec, &mut buf);
        writer.write_all(&buf)?;
    }
    Ok(())
}

/// Read a native trace file
pub fn read_native_trace(data: &[u8]) -> Result<(NativeTraceHeader, Vec<TraceRecord>), TraceFormatError> {
    let hdr = NativeTraceHeader::parse(data)?;
    let mut records = Vec::with_capacity(hdr.record_count as usize);
    let mut offset = NativeTraceHeader::SIZE;
    while offset + 51 <= data.len() {
        if let Some(rec) = deserialize_record(data, offset) {
            records.push(rec);
            offset += 51;
        } else {
            break;
        }
    }
    Ok((hdr, records))
}

// ═══════════════════════════════════════════════════════════════════════════════
// DRCOV FORMAT
// ═══════════════════════════════════════════════════════════════════════════════

/// One entry in a drcov log — a basic block coverage record
#[derive(Debug, Clone)]
pub struct DrcovBbEntry {
    pub start: u32,
    pub size: u16,
    pub mod_id: u16,
}

/// A drcov module entry
#[derive(Debug, Clone)]
pub struct DrcovModule {
    pub id: u32,
    pub base: u64,
    pub end: u64,
    pub entry: u64,
    pub path: String,
}

impl DrcovModule {
    #[must_use]
    pub const fn contains_rva(&self, rva: u64) -> bool { rva >= self.base && rva < self.end }
    #[must_use]
    pub const fn size(&self) -> u64 { self.end.saturating_sub(self.base) }
}

/// Parse a drcov log (text header + binary bb table)
pub fn parse_drcov(data: &[u8]) -> Result<(Vec<DrcovModule>, Vec<DrcovBbEntry>), TraceFormatError> {
    // Find the header/binary boundary by scanning for "BB Table:"
    let text = std::str::from_utf8(data)
        .map_err(|e| TraceFormatError::ParseError(e.to_string()))?;

    let mut modules = Vec::new();
    let mut bb_table_offset = None;
    let mut bb_count = 0usize;

    for line in text.lines() {
        if line.starts_with("DRCOV VERSION:") { continue; }
        if line.starts_with("DRCOV FLAVOR:") { continue; }
        if line.starts_with("Module Table:") { continue; }
        if line.starts_with("Columns:") { continue; }
        if line.starts_with("BB Table:") {
            // Format: "BB Table: N bbs"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                bb_count = parts[2].parse().unwrap_or(0);
            }
            // Binary data starts after this line + newline
            let pos = text.find("BB Table:").unwrap_or(0);
            if let Some(newline_pos) = data[pos..].iter().position(|&b| b == b'\n') {
                bb_table_offset = Some(pos + newline_pos + 1);
            }
            break;
        }
        // Parse module line: " 0, 0x...base, 0x...end, 0x...entry, /path/to/module"
        if let Some(stripped) = line.strip_prefix(' ') {
            if let Some(m) = parse_drcov_module_line(stripped) {
                modules.push(m);
            }
        }
    }

    let mut bbs = Vec::with_capacity(bb_count);
    if let Some(off) = bb_table_offset {
        let bin = &data[off..];
        const BB_SIZE: usize = 8;
        for i in 0..bb_count.min(bin.len() / BB_SIZE) {
            let b = &bin[i * BB_SIZE..];
            bbs.push(DrcovBbEntry {
                start: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                size: u16::from_le_bytes([b[4], b[5]]),
                mod_id: u16::from_le_bytes([b[6], b[7]]),
            });
        }
    }

    Ok((modules, bbs))
}

fn parse_drcov_module_line(line: &str) -> Option<DrcovModule> {
    let parts: Vec<&str> = line.splitn(5, ',').collect();
    if parts.len() < 5 { return None; }
    let id: u32 = parts[0].trim().parse().ok()?;
    let base = u64::from_str_radix(parts[1].trim().trim_start_matches("0x"), 16).ok()?;
    let end = u64::from_str_radix(parts[2].trim().trim_start_matches("0x"), 16).ok()?;
    let entry = u64::from_str_radix(parts[3].trim().trim_start_matches("0x"), 16).ok()?;
    let path = parts[4].trim().to_string();
    Some(DrcovModule { id, base, end, entry, path })
}

/// Convert drcov records to normalized `TraceRecords` (as `BasicBlock` events)
#[must_use]
pub fn drcov_to_trace_records(modules: &[DrcovModule], bbs: &[DrcovBbEntry]) -> Vec<TraceRecord> {
    bbs.iter().enumerate().map(|(i, bb)| {
        let base = modules.get(bb.mod_id as usize).map(|m| m.base).unwrap_or(0);
        let abs_addr = base + u64::from(bb.start);
        TraceRecord::new_bb(i as u64, 0, abs_addr, u32::from(bb.size))
    }).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// FRIDA JSON FORMAT
// ═══════════════════════════════════════════════════════════════════════════════

/// Minimal Frida `GumStalker` event structure parsed from JSON
#[derive(Debug, Clone)]
pub struct FridaTraceEvent {
    pub kind: String,
    pub location: u64,
    pub target: u64,
    pub depth: i32,
}

/// Parse Frida's JSON trace output (array of event objects)
/// Expected format: [{"type":"call","location":"0x...","target":"0x...","depth":N}, ...]
pub fn parse_frida_json_trace(json: &str) -> Result<Vec<FridaTraceEvent>, TraceFormatError> {
    let mut events = Vec::new();
    // Minimal parser without full JSON dependency
    for line in json.lines() {
        let line = line.trim().trim_start_matches('[').trim_end_matches(']');
        if line.is_empty() || line == "," { continue; }
        let line = line.trim().trim_start_matches('{').trim_end_matches('}')
            .trim_end_matches(',');
        let mut kind = String::new();
        let mut location = 0u64;
        let mut target = 0u64;
        let mut depth = 0i32;

        for kv in line.split(',') {
            let parts: Vec<&str> = kv.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }
            let key = parts[0].trim().trim_matches('"');
            let val = parts[1].trim().trim_matches('"');
            match key {
                "type" => kind = val.to_string(),
                "location" => location = parse_hex_or_dec(val),
                "target" => target = parse_hex_or_dec(val),
                "depth" => depth = val.parse().unwrap_or(0),
                _ => {}
            }
        }

        if !kind.is_empty() {
            events.push(FridaTraceEvent { kind, location, target, depth });
        }
    }
    Ok(events)
}

fn parse_hex_or_dec(s: &str) -> u64 {
    let s = s.trim().trim_matches('"');
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// Convert Frida events to normalized `TraceRecords`
#[must_use]
pub fn frida_to_trace_records(events: &[FridaTraceEvent]) -> Vec<TraceRecord> {
    events.iter().enumerate().map(|(i, ev)| {
        let event = match ev.kind.as_str() {
            "call" => TraceEventKind::Call,
            "ret" | "return" => TraceEventKind::Return,
            "exec" => TraceEventKind::Instruction,
            "block" => TraceEventKind::BasicBlock,
            _ => TraceEventKind::Unknown,
        };
        TraceRecord {
            seq: i as u64,
            tid: 0,
            pc: ev.location,
            event,
            aux: ev.target,
            mem_addr: 0,
            mem_size: 0,
            insn_bytes: vec![],
        }
    }).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// CSV FORMAT
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse a simple CSV trace: one record per line, fields: seq,tid,pc,event,aux
pub fn parse_csv_trace(text: &str) -> Result<Vec<TraceRecord>, TraceFormatError> {
    let mut records = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 {
            return Err(TraceFormatError::ParseError(
                format!("line {}: expected at least 3 fields", line_no + 1)));
        }
        let seq: u64 = fields[0].trim().parse().unwrap_or(records.len() as u64);
        let tid: u32 = fields[1].trim().parse().unwrap_or(0);
        let pc = parse_hex_or_dec(fields[2].trim());
        let event = if fields.len() > 3 {
            parse_event_name(fields[3].trim())
        } else {
            TraceEventKind::Instruction
        };
        let aux = if fields.len() > 4 { parse_hex_or_dec(fields[4].trim()) } else { 0 };
        records.push(TraceRecord { seq, tid, pc, event, aux, mem_addr: 0, mem_size: 0, insn_bytes: vec![] });
    }
    Ok(records)
}

fn parse_event_name(s: &str) -> TraceEventKind {
    match s {
        "insn" | "instruction" => TraceEventKind::Instruction,
        "call" => TraceEventKind::Call,
        "ret" | "return" => TraceEventKind::Return,
        "branch" | "br" => TraceEventKind::Branch,
        "mem_read" | "read" => TraceEventKind::MemRead,
        "mem_write" | "write" => TraceEventKind::MemWrite,
        "syscall" => TraceEventKind::Syscall,
        "bb" | "basic_block" => TraceEventKind::BasicBlock,
        "exception" => TraceEventKind::Exception,
        _ => TraceEventKind::Unknown,
    }
}

/// Write records in CSV format
pub fn write_csv_trace<W: Write>(writer: &mut W, records: &[TraceRecord]) -> Result<(), TraceFormatError> {
    writeln!(writer, "#seq,tid,pc,event,aux,mem_addr,mem_size")?;
    for r in records {
        writeln!(writer, "{},{},{:#018x},{},{:#018x},{:#018x},{}",
            r.seq, r.tid, r.pc, r.event.name(), r.aux, r.mem_addr, r.mem_size)?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEL PT (simplified)
// ═══════════════════════════════════════════════════════════════════════════════

/// Recognized Intel PT packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtPacketType {
    Pad,       // 0x00
    Psb,       // Packet Stream Boundary
    Psbend,    // PSB end
    Tip,       // Target IP (indirect branch)
    TipPge,    // TIP.PGE (enable)
    TipPgd,    // TIP.PGD (disable)
    Fup,       // Flow Update Packet
    Tnt8,      // Taken/Not-Taken (8 bits)
    Tnt64,     // Taken/Not-Taken (64 bits)
    Pip,       // Paging Info Packet
    Mode,      // Mode packet
    Tsc,       // Timestamp Counter
    Cbr,       // Core Bus Ratio
    Ovf,       // Overflow
    Unknown,
}

/// Simplified PT packet (carries extracted data)
#[derive(Debug, Clone)]
pub struct PtPacket {
    pub ptype: PtPacketType,
    /// Size in bytes
    pub size: usize,
    /// Extracted IP (for TIP, FUP packets)
    pub ip: Option<u64>,
    /// Taken/Not-Taken bits for TNT
    pub tnt_bits: Option<u64>,
    pub tnt_count: u8,
    /// TSC value
    pub tsc: Option<u64>,
}

/// Scan a raw Intel PT packet stream and emit packets
#[must_use]
pub fn decode_pt_packets(data: &[u8]) -> Vec<PtPacket> {
    let mut packets = Vec::new();
    let mut i = 0usize;
    let mut last_ip: u64 = 0;

    while i < data.len() {
        let byte0 = data[i];
        match byte0 {
            0x00 => { packets.push(PtPacket { ptype: PtPacketType::Pad, size: 1, ip: None, tnt_bits: None, tnt_count: 0, tsc: None }); i += 1; }
            0x02 if i + 1 < data.len() && data[i+1] == 0x82 => {
                // PSB
                packets.push(PtPacket { ptype: PtPacketType::Psb, size: 16, ip: None, tnt_bits: None, tnt_count: 0, tsc: None });
                i += 16.min(data.len() - i);
            }
            b if b & 0x01 == 0 && b & 0xFE != 0 => {
                // TNT8: bits 7:1 are TNT bits, bit 0 = 0
                // Highest set bit index = position of the stop bit; the
                // number of TNT bits below it equals that index.
                let cnt = (7 - b.leading_zeros()) as u8;
                let bits = (u64::from(b) >> 1) & ((1 << cnt) - 1);
                packets.push(PtPacket { ptype: PtPacketType::Tnt8, size: 1, ip: None, tnt_bits: Some(bits), tnt_count: cnt, tsc: None });
                i += 1;
            }
            0x0D | 0x1D | 0x2D | 0x3D => {
                // TIP variants; IP compression: bits [4:3] of byte0
                let ip_mode = (byte0 >> 3) & 0x03;
                let (new_ip, sz) = decode_pt_ip(data, i + 1, last_ip, ip_mode);
                let ptype = match byte0 & 0x1F {
                    0x0D => PtPacketType::Tip,
                    0x11 => PtPacketType::TipPge,
                    0x01 => PtPacketType::TipPgd,
                    0x1D => PtPacketType::Fup,
                    _ => PtPacketType::Tip,
                };
                last_ip = new_ip;
                packets.push(PtPacket { ptype, size: 1 + sz, ip: Some(new_ip), tnt_bits: None, tnt_count: 0, tsc: None });
                i += 1 + sz;
            }
            0x19 if i + 7 < data.len() => {
                // TSC
                let ts = u64::from_le_bytes([data[i+1],data[i+2],data[i+3],data[i+4],data[i+5],data[i+6],data[i+7],0]) & 0x00FFFFFFFFFFFFFF;
                packets.push(PtPacket { ptype: PtPacketType::Tsc, size: 8, ip: None, tnt_bits: None, tnt_count: 0, tsc: Some(ts) });
                i += 8;
            }
            _ => { i += 1; }
        }
    }
    packets
}

fn decode_pt_ip(data: &[u8], offset: usize, last_ip: u64, mode: u8) -> (u64, usize) {
    match mode {
        0 => (0, 0),
        1 => {
            if offset + 2 > data.len() { return (0, 0); }
            let update = u64::from(u16::from_le_bytes([data[offset], data[offset+1]]));
            let ip = (last_ip & !0xFFFF) | update;
            (ip, 2)
        }
        2 => {
            if offset + 4 > data.len() { return (0, 0); }
            let update = u64::from(u32::from_le_bytes([data[offset],data[offset+1],data[offset+2],data[offset+3]]));
            let ip = (last_ip & !0xFFFFFFFF) | update;
            (ip, 4)
        }
        3 => {
            if offset + 6 > data.len() { return (0, 0); }
            let mut bytes = [0u8; 8];
            bytes[..6].copy_from_slice(&data[offset..offset+6]);
            let raw = u64::from_le_bytes(bytes);
            // Sign-extend bit 47
            let ip = if raw & (1 << 47) != 0 { raw | 0xFFFF000000000000 } else { raw };
            (ip, 6)
        }
        _ => (0, 0),
    }
}

/// Convert decoded PT packets into normalized `TraceRecords`
#[must_use]
pub fn pt_to_trace_records(packets: &[PtPacket]) -> Vec<TraceRecord> {
    let mut records = Vec::new();
    let mut seq = 0u64;
    for pkt in packets {
        match pkt.ptype {
            PtPacketType::Tip => {
                if let Some(ip) = pkt.ip {
                    records.push(TraceRecord::new_call(seq, 0, 0, ip));
                    seq += 1;
                }
            }
            PtPacketType::Fup => {
                if let Some(ip) = pkt.ip {
                    records.push(TraceRecord::new_insn(seq, 0, ip));
                    seq += 1;
                }
            }
            PtPacketType::Tnt8 => {
                if let (Some(bits), cnt) = (pkt.tnt_bits, pkt.tnt_count) {
                    for b in 0..cnt {
                        let taken = (bits >> b) & 1 != 0;
                        records.push(TraceRecord {
                            seq, tid: 0, pc: 0,
                            event: TraceEventKind::Branch,
                            aux: u64::from(taken),
                            mem_addr: 0, mem_size: 0, insn_bytes: vec![],
                        });
                        seq += 1;
                    }
                }
            }
            _ => {}
        }
    }
    records
}

// ── Format detection ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFormat {
    NativeBinary,
    Drcov,
    FridaJson,
    Csv,
    IntelPt,
    Unknown,
}

/// Detect the format of a trace file from its first bytes
#[must_use]
pub fn detect_format(data: &[u8]) -> TraceFormat {
    if data.len() >= 4 && &data[..4] == b"RTRC" {
        return TraceFormat::NativeBinary;
    }
    if data.starts_with(b"DRCOV VERSION:") {
        return TraceFormat::Drcov;
    }
    if let Ok(s) = std::str::from_utf8(&data[..data.len().min(256)]) {
        let s = s.trim();
        if s.starts_with('[') && s.contains("\"type\"") {
            return TraceFormat::FridaJson;
        }
        if s.starts_with('#') || s.contains(',') {
            return TraceFormat::Csv;
        }
    }
    TraceFormat::Unknown
}

/// Auto-detect and parse any supported trace format
pub fn parse_auto(data: &[u8]) -> Result<Vec<TraceRecord>, TraceFormatError> {
    match detect_format(data) {
        TraceFormat::NativeBinary => {
            let (_, records) = read_native_trace(data)?;
            Ok(records)
        }
        TraceFormat::Drcov => {
            let (mods, bbs) = parse_drcov(data)?;
            Ok(drcov_to_trace_records(&mods, &bbs))
        }
        TraceFormat::FridaJson => {
            let s = std::str::from_utf8(data)
                .map_err(|e| TraceFormatError::ParseError(e.to_string()))?;
            let evs = parse_frida_json_trace(s)?;
            Ok(frida_to_trace_records(&evs))
        }
        TraceFormat::Csv => {
            let s = std::str::from_utf8(data)
                .map_err(|e| TraceFormatError::ParseError(e.to_string()))?;
            parse_csv_trace(s)
        }
        TraceFormat::IntelPt => {
            let pkts = decode_pt_packets(data);
            Ok(pt_to_trace_records(&pkts))
        }
        TraceFormat::Unknown => Err(TraceFormatError::ParseError("unknown format".to_string())),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_header_roundtrip() {
        let hdr = NativeTraceHeader::new(100, 1234, 1);
        let bytes = hdr.serialize();
        assert_eq!(bytes.len(), NativeTraceHeader::SIZE);
        let hdr2 = NativeTraceHeader::parse(&bytes).unwrap();
        assert_eq!(hdr2.magic, NATIVE_MAGIC);
        assert_eq!(hdr2.record_count, 100);
        assert_eq!(hdr2.pid, 1234);
        assert_eq!(hdr2.arch, 1);
    }

    #[test]
    fn test_native_header_bad_magic() {
        let mut bytes = NativeTraceHeader::new(0, 0, 0).serialize();
        bytes[0] = b'X';
        assert!(matches!(NativeTraceHeader::parse(&bytes), Err(TraceFormatError::BadMagic(_))));
    }

    #[test]
    fn test_serialize_deserialize_record() {
        let rec = TraceRecord::new_call(42, 1, 0x1000, 0x2000);
        let mut buf = Vec::new();
        serialize_record(&rec, &mut buf);
        // We padded to 51 bytes
        assert_eq!(buf.len(), 51);
        let rec2 = deserialize_record(&buf, 0).unwrap();
        assert_eq!(rec2.seq, 42);
        assert_eq!(rec2.tid, 1);
        assert_eq!(rec2.pc, 0x1000);
        assert_eq!(rec2.aux, 0x2000);
        assert_eq!(rec2.event, TraceEventKind::Call);
    }

    #[test]
    fn test_write_read_native_trace() {
        let records = vec![
            TraceRecord::new_insn(0, 0, 0x1000),
            TraceRecord::new_call(1, 0, 0x1010, 0x2000),
            TraceRecord::new_bb(2, 0, 0x2000, 20),
        ];
        let mut buf = Vec::new();
        write_native_trace(&mut buf, &records, 9999, 1).unwrap();
        let (hdr, recs2) = read_native_trace(&buf).unwrap();
        assert_eq!(hdr.record_count, 3);
        assert_eq!(recs2.len(), 3);
        assert_eq!(recs2[1].event, TraceEventKind::Call);
    }

    #[test]
    fn test_detect_format_native() {
        let data = NativeTraceHeader::new(0, 0, 0).serialize();
        assert_eq!(detect_format(&data), TraceFormat::NativeBinary);
    }

    #[test]
    fn test_detect_format_csv() {
        let data = b"#seq,tid,pc\n0,0,0x1000\n";
        assert_eq!(detect_format(data), TraceFormat::Csv);
    }

    #[test]
    fn test_parse_csv_trace() {
        let csv = "#seq,tid,pc,event,aux\n0,0,0x1000,call,0x2000\n1,0,0x2000,insn,0\n";
        let records = parse_csv_trace(csv).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].pc, 0x1000);
        assert_eq!(records[0].event, TraceEventKind::Call);
        assert_eq!(records[0].aux, 0x2000);
        assert_eq!(records[1].event, TraceEventKind::Instruction);
    }

    #[test]
    fn test_pt_tnt8_decode() {
        // TNT8 byte: 0b00000110 = two TNT bits: taken, not-taken
        let data = [0x06u8];
        let pkts = decode_pt_packets(&data);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].ptype, PtPacketType::Tnt8);
        assert_eq!(pkts[0].tnt_count, 2);
    }
}
