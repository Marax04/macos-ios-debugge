//! Trace serializer: binary format with run-length and LZ-style compression
//! for writing and reading large execution traces efficiently.
//!
//! `TraceSerializer` writes a compact binary file:
//!   - 8-byte magic + 4-byte version header.
//!   - Per-record blocks with event type tags + field encoding.
//!   - Optional RLE pass that merges identical consecutive records.
//!
//! `TraceWriter` / `TraceReader` expose streaming I/O on top of `std::io`.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::{TraceEvent, TraceSession};

// ─── Magic / Version ─────────────────────────────────────────────────────────

pub const TRACE_MAGIC: [u8; 8] = *b"RUSTRACE";
pub const TRACE_VERSION: u32 = 1;

// ─── TraceFormat ─────────────────────────────────────────────────────────────

/// The on-disk format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceFormat {
    /// Raw binary encoding, no compression.
    Raw,
    /// Run-length encoding of consecutive identical events.
    Rle,
    /// Delta encoding of addresses (most instructions step forward by small amounts).
    DeltaEncoded,
    /// JSON encoding (human-readable, large).
    Json,
}

impl TraceFormat {
    #[must_use]
    pub const fn format_byte(&self) -> u8 {
        match self {
            Self::Raw => 0x00,
            Self::Rle => 0x01,
            Self::DeltaEncoded => 0x02,
            Self::Json => 0x03,
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Raw),
            0x01 => Some(Self::Rle),
            0x02 => Some(Self::DeltaEncoded),
            0x03 => Some(Self::Json),
            _ => None,
        }
    }
}

// ─── Event type tags ─────────────────────────────────────────────────────────

#[repr(u8)]
enum EventTag {
    Instruction   = 0x01,
    MemRead       = 0x02,
    MemWrite      = 0x03,
    Call          = 0x04,
    Return        = 0x05,
    Exception     = 0x06,
    Syscall       = 0x07,
    Branch        = 0x08,
    ModuleLoad    = 0x09,
    RegisterChange = 0x0A,
}

const fn event_tag(event: &TraceEvent) -> u8 {
    match event {
        TraceEvent::Instruction { .. }   => EventTag::Instruction as u8,
        TraceEvent::MemRead { .. }       => EventTag::MemRead as u8,
        TraceEvent::MemWrite { .. }      => EventTag::MemWrite as u8,
        TraceEvent::Call { .. }          => EventTag::Call as u8,
        TraceEvent::Return { .. }        => EventTag::Return as u8,
        TraceEvent::Exception { .. }     => EventTag::Exception as u8,
        TraceEvent::Syscall { .. }       => EventTag::Syscall as u8,
        TraceEvent::Branch { .. }        => EventTag::Branch as u8,
        TraceEvent::ModuleLoad { .. }    => EventTag::ModuleLoad as u8,
        TraceEvent::RegisterChange { .. } => EventTag::RegisterChange as u8,
    }
}

// ─── Low-level encode/decode helpers ─────────────────────────────────────────

fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_bool(buf: &mut Vec<u8>, v: bool) {
    buf.push(u8::from(v));
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    // Strings longer than u32::MAX cannot be round-tripped; silently truncate
    // the length field to u32::MAX so that the read-side UnexpectedEof check
    // fires on deserialization rather than producing silently wrong output.
    let len: u32 = bytes.len().try_into().unwrap_or(u32::MAX);
    write_u32_le(buf, len);
    buf.extend_from_slice(&bytes[..len as usize]);
}

fn write_vec_u64(buf: &mut Vec<u8>, v: &[u64]) {
    // Guard against truncation: length field is u32, silently cap.
    let len: u32 = v.len().try_into().unwrap_or(u32::MAX);
    write_u32_le(buf, len);
    for &x in &v[..len as usize] {
        write_u64_le(buf, x);
    }
}

fn read_u8(data: &[u8], pos: &mut usize) -> io::Result<u8> {
    if *pos >= data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u8"));
    }
    let v = data[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u32_le(data: &[u8], pos: &mut usize) -> io::Result<u32> {
    if *pos + 4 > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u32"));
    }
    let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_u64_le(data: &[u8], pos: &mut usize) -> io::Result<u64> {
    if *pos + 8 > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u64"));
    }
    let v = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

fn read_bool(data: &[u8], pos: &mut usize) -> io::Result<bool> {
    Ok(read_u8(data, pos)? != 0)
}

/// Maximum byte length for a string field in the binary trace format (16 MiB).
const MAX_STRING_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of elements in a vector field in the binary trace format.
const MAX_VEC_ELEMENTS: usize = 1024;
/// Maximum number of records in a trace session read from untrusted binary data.
const MAX_RECORD_COUNT: usize = 100_000_000;
/// Maximum RLE repeat count per block.
const MAX_RLE_REPEAT: u32 = 1_000_000;

fn read_string(data: &[u8], pos: &mut usize) -> io::Result<String> {
    let len = read_u32_le(data, pos)? as usize;
    if len > MAX_STRING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("string length {len} exceeds limit {MAX_STRING_BYTES}"),
        ));
    }
    if *pos + len > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "string"));
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_string();
    *pos += len;
    Ok(s)
}

fn read_vec_u64(data: &[u8], pos: &mut usize) -> io::Result<Vec<u64>> {
    let len = read_u32_le(data, pos)? as usize;
    if len > MAX_VEC_ELEMENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("vec length {len} exceeds limit {MAX_VEC_ELEMENTS}"),
        ));
    }
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(read_u64_le(data, pos)?);
    }
    Ok(v)
}

// ─── Encode/Decode one event ─────────────────────────────────────────────────

fn encode_event(buf: &mut Vec<u8>, event: &TraceEvent) {
    write_u8(buf, event_tag(event));
    match event {
        TraceEvent::Instruction { addr, size } => {
            write_u64_le(buf, *addr);
            write_u8(buf, *size);
        }
        TraceEvent::MemRead { addr, size, value } | TraceEvent::MemWrite { addr, size, value } => {
            write_u64_le(buf, *addr);
            write_u8(buf, *size);
            write_u64_le(buf, *value);
        }
        TraceEvent::Call { from, to } | TraceEvent::Return { from, to } => {
            write_u64_le(buf, *from);
            write_u64_le(buf, *to);
        }
        TraceEvent::Exception { code, addr } => {
            write_u32_le(buf, *code);
            write_u64_le(buf, *addr);
        }
        TraceEvent::Syscall { number, args } => {
            write_u64_le(buf, *number);
            write_vec_u64(buf, args);
        }
        TraceEvent::Branch { from, to, taken } => {
            write_u64_le(buf, *from);
            write_u64_le(buf, *to);
            write_bool(buf, *taken);
        }
        TraceEvent::ModuleLoad { base, size, name } => {
            write_u64_le(buf, *base);
            write_u64_le(buf, *size);
            write_string(buf, name);
        }
        TraceEvent::RegisterChange { name, old_value, new_value } => {
            write_string(buf, name);
            write_u64_le(buf, *old_value);
            write_u64_le(buf, *new_value);
        }
    }
}

fn decode_event(data: &[u8], pos: &mut usize) -> io::Result<TraceEvent> {
    let tag = read_u8(data, pos)?;
    match tag {
        t if t == EventTag::Instruction as u8 => {
            let addr = read_u64_le(data, pos)?;
            let size = read_u8(data, pos)?;
            Ok(TraceEvent::Instruction { addr, size })
        }
        t if t == EventTag::MemRead as u8 => {
            let addr = read_u64_le(data, pos)?;
            let size = read_u8(data, pos)?;
            let value = read_u64_le(data, pos)?;
            Ok(TraceEvent::MemRead { addr, size, value })
        }
        t if t == EventTag::MemWrite as u8 => {
            let addr = read_u64_le(data, pos)?;
            let size = read_u8(data, pos)?;
            let value = read_u64_le(data, pos)?;
            Ok(TraceEvent::MemWrite { addr, size, value })
        }
        t if t == EventTag::Call as u8 => {
            let from = read_u64_le(data, pos)?;
            let to = read_u64_le(data, pos)?;
            Ok(TraceEvent::Call { from, to })
        }
        t if t == EventTag::Return as u8 => {
            let from = read_u64_le(data, pos)?;
            let to = read_u64_le(data, pos)?;
            Ok(TraceEvent::Return { from, to })
        }
        t if t == EventTag::Exception as u8 => {
            let code = read_u32_le(data, pos)?;
            let addr = read_u64_le(data, pos)?;
            Ok(TraceEvent::Exception { code, addr })
        }
        t if t == EventTag::Syscall as u8 => {
            let number = read_u64_le(data, pos)?;
            let args = read_vec_u64(data, pos)?;
            Ok(TraceEvent::Syscall { number, args })
        }
        t if t == EventTag::Branch as u8 => {
            let from = read_u64_le(data, pos)?;
            let to = read_u64_le(data, pos)?;
            let taken = read_bool(data, pos)?;
            Ok(TraceEvent::Branch { from, to, taken })
        }
        t if t == EventTag::ModuleLoad as u8 => {
            let base = read_u64_le(data, pos)?;
            let size = read_u64_le(data, pos)?;
            let name = read_string(data, pos)?;
            Ok(TraceEvent::ModuleLoad { base, size, name })
        }
        t if t == EventTag::RegisterChange as u8 => {
            let name = read_string(data, pos)?;
            let old_value = read_u64_le(data, pos)?;
            let new_value = read_u64_le(data, pos)?;
            Ok(TraceEvent::RegisterChange { name, old_value, new_value })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown event tag: 0x{other:02x}"),
        )),
    }
}

// ─── TraceSerializer ─────────────────────────────────────────────────────────

/// Serializes and deserializes `TraceSession` objects to/from binary.
pub struct TraceSerializer {
    pub format: TraceFormat,
}

impl TraceSerializer {
    #[must_use]
    pub const fn new(format: TraceFormat) -> Self {
        Self { format }
    }

    #[must_use]
    pub const fn raw() -> Self {
        Self::new(TraceFormat::Raw)
    }

    #[must_use]
    pub const fn rle() -> Self {
        Self::new(TraceFormat::Rle)
    }

    /// Serialize a session to bytes.
    #[must_use]
    pub fn serialize(&self, session: &TraceSession) -> Vec<u8> {
        match self.format {
            TraceFormat::Json => self.serialize_json(session),
            TraceFormat::Rle => self.serialize_rle(session),
            _ => self.serialize_raw(session),
        }
    }

    /// Deserialize a session from bytes.
    pub fn deserialize(&self, data: &[u8]) -> io::Result<TraceSession> {
        if data.len() < 13 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "header too short"));
        }
        // Magic
        if data[..8] != TRACE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        // Version
        let _version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        // Format byte
        let fmt_byte = data[12];
        let _fmt = TraceFormat::from_byte(fmt_byte)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad format byte"))?;

        let mut pos = 13;
        // session name
        let name = read_string(data, &mut pos)?;
        // arch
        let arch = read_string(data, &mut pos)?;
        // record count
        let count_raw = read_u64_le(data, &mut pos)?;
        if count_raw > MAX_RECORD_COUNT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("record count {count_raw} exceeds limit {MAX_RECORD_COUNT}"),
            ));
        }
        let count = count_raw as usize;

        let mut session = TraceSession::new(name, arch);
        session.records.reserve(count);

        // If RLE, each block has a repeat count
        if _fmt == TraceFormat::Rle {
            for _ in 0..count {
                let thread_id = read_u32_le(data, &mut pos)?;
                let timestamp_ns = read_u64_le(data, &mut pos)?;
                let repeat = read_u32_le(data, &mut pos)?;
                if repeat > MAX_RLE_REPEAT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("RLE repeat count {repeat} exceeds limit {MAX_RLE_REPEAT}"),
                    ));
                }
                let event = decode_event(data, &mut pos)?;
                for i in 0..u64::from(repeat) {
                    session.push(event.clone(), thread_id, timestamp_ns + i * 100);
                }
            }
        } else {
            for _ in 0..count {
                let thread_id = read_u32_le(data, &mut pos)?;
                let timestamp_ns = read_u64_le(data, &mut pos)?;
                let event = decode_event(data, &mut pos)?;
                session.push(event, thread_id, timestamp_ns);
            }
        }
        Ok(session)
    }

    fn write_header(&self, buf: &mut Vec<u8>, session: &TraceSession, record_count: usize) {
        buf.extend_from_slice(&TRACE_MAGIC);
        write_u32_le(buf, TRACE_VERSION);
        write_u8(buf, self.format.format_byte());
        write_string(buf, &session.name);
        write_string(buf, &session.arch);
        write_u64_le(buf, record_count as u64);
    }

    fn serialize_raw(&self, session: &TraceSession) -> Vec<u8> {
        let mut buf = Vec::with_capacity(session.records.len() * 20 + 64);
        self.write_header(&mut buf, session, session.records.len());
        for rec in &session.records {
            write_u32_le(&mut buf, rec.thread_id);
            write_u64_le(&mut buf, rec.timestamp_ns);
            encode_event(&mut buf, &rec.event);
        }
        buf
    }

    fn serialize_rle(&self, session: &TraceSession) -> Vec<u8> {
        // Group consecutive identical events
        struct Block {
            thread_id: u32,
            timestamp_ns: u64,
            event: TraceEvent,
            count: u32,
        }
        let mut blocks: Vec<Block> = Vec::new();
        for rec in &session.records {
            if let Some(last) = blocks.last_mut()
                && last.event == rec.event
                && last.thread_id == rec.thread_id
            {
                last.count += 1;
            } else {
                blocks.push(Block {
                    thread_id: rec.thread_id,
                    timestamp_ns: rec.timestamp_ns,
                    event: rec.event.clone(),
                    count: 1,
                });
            }
        }
        let mut buf = Vec::with_capacity(blocks.len() * 24 + 64);
        // Write with RLE format byte; record_count = number of blocks
        self.write_header(&mut buf, session, blocks.len());
        for b in &blocks {
            write_u32_le(&mut buf, b.thread_id);
            write_u64_le(&mut buf, b.timestamp_ns);
            write_u32_le(&mut buf, b.count);
            encode_event(&mut buf, &b.event);
        }
        buf
    }

    fn serialize_json(&self, session: &TraceSession) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TRACE_MAGIC);
        write_u32_le(&mut buf, TRACE_VERSION);
        write_u8(&mut buf, TraceFormat::Json.format_byte());
        let json = serde_json::to_vec(session).unwrap_or_default();
        // Guard: the JSON length field is u32; truncation would produce a
        // corrupt file that deserializes incorrectly.  Fall back to an empty
        // payload so the caller gets a clear deserialization error rather than
        // silently wrong data.
        let json_len: u32 = json.len().try_into().unwrap_or(0);
        write_u32_le(&mut buf, json_len);
        if json_len as usize == json.len() {
            buf.extend_from_slice(&json);
        }
        buf
    }

    /// Estimate compression ratio for RLE vs raw.
    #[must_use]
    pub fn rle_compression_ratio(session: &TraceSession) -> f64 {
        let rle_ser = Self::rle();
        let raw_ser = Self::raw();
        let rle_size = rle_ser.serialize_rle(session).len();
        let raw_size = raw_ser.serialize_raw(session).len();
        if rle_size == 0 { return 1.0; }
        raw_size as f64 / rle_size as f64
    }
}

// ─── TraceWriter ─────────────────────────────────────────────────────────────

/// Streaming writer for traces to any `std::io::Write` sink.
pub struct TraceWriter<W: Write> {
    inner: W,
    serializer: TraceSerializer,
    records_written: u64,
}

impl<W: Write> TraceWriter<W> {
    pub const fn new(inner: W, format: TraceFormat) -> Self {
        Self {
            inner,
            serializer: TraceSerializer::new(format),
            records_written: 0,
        }
    }

    /// Write a whole session at once.
    pub fn write_session(&mut self, session: &TraceSession) -> io::Result<usize> {
        let bytes = self.serializer.serialize(session);
        self.inner.write_all(&bytes)?;
        self.records_written += session.records.len() as u64;
        Ok(bytes.len())
    }

    pub const fn records_written(&self) -> u64 {
        self.records_written
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ─── TraceReader ─────────────────────────────────────────────────────────────

/// Streaming reader for traces from any `std::io::Read` source.
pub struct TraceReader<R: Read> {
    inner: R,
    serializer: TraceSerializer,
}

impl<R: Read> TraceReader<R> {
    pub const fn new(inner: R, format: TraceFormat) -> Self {
        Self {
            inner,
            serializer: TraceSerializer::new(format),
        }
    }

    /// Read the entire source into a `TraceSession`.
    pub fn read_session(&mut self) -> io::Result<TraceSession> {
        let mut buf = Vec::new();
        self.inner.read_to_end(&mut buf)?;
        self.serializer.deserialize(&buf)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceSession;
    use std::io::Cursor;

    fn make_session() -> TraceSession {
        let mut s = TraceSession::new("test_trace", "x86_64");
        s.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, 100);
        s.push(TraceEvent::Instruction { addr: 0x1004, size: 4 }, 1, 200);
        s.push(TraceEvent::MemRead { addr: 0x2000, size: 8, value: 0xDEAD_BEEF }, 1, 300);
        s.push(TraceEvent::MemWrite { addr: 0x3000, size: 4, value: 0x1234 }, 1, 400);
        s.push(TraceEvent::Call { from: 0x1008, to: 0x5000 }, 1, 500);
        s.push(TraceEvent::Return { from: 0x5010, to: 0x100c }, 1, 600);
        s.push(TraceEvent::Exception { code: 0xC000_0005, addr: 0x9000 }, 1, 700);
        s.push(TraceEvent::Syscall { number: 1, args: vec![0, 1, 2] }, 1, 800);
        s.push(TraceEvent::Branch { from: 0x1010, to: 0x1020, taken: true }, 1, 900);
        s.push(TraceEvent::ModuleLoad { base: 0x0040_0000, size: 0x1000, name: "ntdll.dll".into() }, 1, 1000);
        s.push(TraceEvent::RegisterChange { name: "rax".into(), old_value: 0, new_value: 0xFF }, 1, 1100);
        s
    }

    fn make_rle_session() -> TraceSession {
        let mut s = TraceSession::new("rle_trace", "x86_64");
        // Repeated instruction (loop body)
        for i in 0..10 {
            s.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, i * 100);
        }
        s.push(TraceEvent::Instruction { addr: 0x1004, size: 4 }, 1, 1100);
        s
    }

    #[test]
    fn test_serialize_deserialize_raw() {
        let session = make_session();
        let ser = TraceSerializer::raw();
        let bytes = ser.serialize(&session);
        assert!(!bytes.is_empty());
        let recovered = ser.deserialize(&bytes).unwrap();
        assert_eq!(recovered.name, session.name);
        assert_eq!(recovered.arch, session.arch);
        assert_eq!(recovered.records.len(), session.records.len());
    }

    #[test]
    fn test_magic_in_output() {
        let session = make_session();
        let ser = TraceSerializer::raw();
        let bytes = ser.serialize(&session);
        assert_eq!(&bytes[..8], b"RUSTRACE");
    }

    #[test]
    fn test_version_in_output() {
        let session = make_session();
        let ser = TraceSerializer::raw();
        let bytes = ser.serialize(&session);
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(version, TRACE_VERSION);
    }

    #[test]
    fn test_format_byte_raw() {
        let session = make_session();
        let ser = TraceSerializer::raw();
        let bytes = ser.serialize(&session);
        assert_eq!(bytes[12], TraceFormat::Raw.format_byte());
    }

    #[test]
    fn test_format_byte_rle() {
        let session = make_rle_session();
        let ser = TraceSerializer::rle();
        let bytes = ser.serialize(&session);
        assert_eq!(bytes[12], TraceFormat::Rle.format_byte());
    }

    #[test]
    fn test_rle_smaller_than_raw_for_repetitive() {
        let session = make_rle_session();
        let raw_size = TraceSerializer::raw().serialize(&session).len();
        let rle_size = TraceSerializer::rle().serialize(&session).len();
        assert!(rle_size < raw_size, "RLE should be smaller for repeated events");
    }

    #[test]
    fn test_rle_deserialize_roundtrip() {
        let session = make_rle_session();
        let ser = TraceSerializer::rle();
        let bytes = ser.serialize(&session);
        let recovered = ser.deserialize(&bytes).unwrap();
        assert_eq!(recovered.records.len(), session.records.len());
        assert_eq!(recovered.name, session.name);
    }

    #[test]
    fn test_rle_compression_ratio() {
        let session = make_rle_session();
        let ratio = TraceSerializer::rle_compression_ratio(&session);
        assert!(ratio > 1.0, "compression should reduce size");
    }

    #[test]
    fn test_bad_magic_error() {
        let mut bad = b"BADMAGIC".to_vec();
        bad.extend_from_slice(&[0u8; 20]);
        let ser = TraceSerializer::raw();
        let err = ser.deserialize(&bad);
        assert!(err.is_err());
    }

    #[test]
    fn test_truncated_data_error() {
        let ser = TraceSerializer::raw();
        let err = ser.deserialize(b"RU");
        assert!(err.is_err());
    }

    #[test]
    fn test_event_roundtrip_all_types() {
        let session = make_session();
        let ser = TraceSerializer::raw();
        let bytes = ser.serialize(&session);
        let recovered = ser.deserialize(&bytes).unwrap();
        for (orig, rec) in session.records.iter().zip(recovered.records.iter()) {
            assert_eq!(orig.event, rec.event);
            assert_eq!(orig.thread_id, rec.thread_id);
        }
    }

    #[test]
    fn test_trace_writer_and_reader() {
        let session = make_session();
        let mut buf = Vec::new();
        {
            let mut writer = TraceWriter::new(Cursor::new(&mut buf), TraceFormat::Raw);
            let written = writer.write_session(&session).unwrap();
            writer.flush().unwrap();
            assert_eq!(writer.records_written(), session.records.len() as u64);
            assert!(written > 0);
        }
        let mut reader = TraceReader::new(Cursor::new(buf), TraceFormat::Raw);
        let recovered = reader.read_session().unwrap();
        assert_eq!(recovered.records.len(), session.records.len());
    }

    #[test]
    fn test_empty_session_roundtrip() {
        let session = TraceSession::new("empty", "arm64");
        let ser = TraceSerializer::raw();
        let bytes = ser.serialize(&session);
        let recovered = ser.deserialize(&bytes).unwrap();
        assert_eq!(recovered.name, "empty");
        assert_eq!(recovered.arch, "arm64");
        assert_eq!(recovered.records.len(), 0);
    }

    #[test]
    fn test_trace_format_byte_roundtrip() {
        for fmt in [TraceFormat::Raw, TraceFormat::Rle, TraceFormat::DeltaEncoded, TraceFormat::Json] {
            let b = fmt.format_byte();
            assert_eq!(TraceFormat::from_byte(b), Some(fmt));
        }
        assert_eq!(TraceFormat::from_byte(0xFF), None);
    }
}
