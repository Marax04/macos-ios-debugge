//! `tpiu_sink` — TPIU / SWO trace sink and frame decoder.
//!
//! Implements the full `CoreSight` TPIU formatter framing protocol as well as the
//! simpler Manchester-encoded SWO / ITM single-wire output (SWO) mode.
//!
//! ## TPIU Formatter
//!
//! The TPIU (Trace Port Interface Unit) formatter multiplexes up to 256 ATB
//! source IDs into a 16-byte framed stream.  Each frame:
//!
//! ```text
//! [byte 0]: 0bxxxxxxx1   ← half-frame header, ID bits 7:1 in bits 7:1, flag in bit 0
//! [bytes 1-6]:  data
//! [byte 7]: 0bxxxxxxx0   ← auxiliary byte; bit 0 distinguishes header vs aux
//! [bytes 8-14]: data
//! [byte 15]: 0bxxxxxxx?  ← second half-frame header or flush byte
//! ```
//!
//! Every byte whose LSB is not part of ATB data is an ID/flag byte; data bytes
//! have their LSB stored in the preceding ID/flag byte.
//!
//! ## SWO / ITM Mode
//!
//! In SWO mode the formatter is bypassed; raw byte-aligned ITM/DWT packets
//! arrive on a single UART-like wire.  The decoder simply passes bytes through
//! to the registered port 0 callback (no multiplexing).

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the TPIU/SWO sink.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpiuError {
    /// No sync pattern was found in the input data.
    #[error("no TPIU sync pattern found")]
    NoSync,
    /// A frame byte had an unexpected structure.
    #[error("malformed frame byte at offset {offset}: 0x{byte:02x}")]
    MalformedFrame {
        /// Byte offset within the raw input stream.
        offset: usize,
        /// The offending byte.
        byte: u8,
    },
    /// The ATB source ID embedded in a frame header changed unexpectedly.
    #[error("ATB ID collision: old={old}, new={new} at frame {frame}")]
    IdCollision {
        /// Previous source ID.
        old: u8,
        /// Incoming source ID.
        new: u8,
        /// Frame index where the collision occurred.
        frame: u64,
    },
    /// The input buffer was truncated mid-frame.
    #[error("truncated input: need {need} bytes, have {have}")]
    Truncated {
        /// Bytes needed to complete the frame.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },
    /// SWO baud-rate mismatch detected via framing error.
    #[error("SWO framing error at offset {0}")]
    SwoFramingError(usize),
}

// ─── TpiuMode ─────────────────────────────────────────────────────────────────

/// Operating mode of the TPIU / SWO trace sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpiuMode {
    /// Full TPIU formatter with 16-byte frames and ATB port multiplexing.
    Formatter,
    /// Manchester-encoded SWO (UART framing, no TPIU formatter).
    Swo,
    /// Raw binary SWO (NRZ encoding, no TPIU formatter).
    SwoNrz,
    /// Parallel trace port — width is carried in the config.
    ParallelPort {
        /// Port width in bits (1, 2, 4, 8, 16, or 32).
        width: u8,
    },
}

// ─── TpiuConfig ───────────────────────────────────────────────────────────────

/// Configuration for a TPIU/SWO sink instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpiuConfig {
    /// Operating mode.
    pub mode: TpiuMode,
    /// Expected SWO baud rate (used for framing validation in SWO modes).
    pub swo_baud: u32,
    /// Clock frequency of the CPU (Hz) — used to derive baud divisors.
    pub cpu_hz: u64,
    /// If true, emit a `TpiuEvent::FrameSync` event on every recovered sync.
    pub emit_sync_events: bool,
    /// If true, drop all data bytes that arrive before the first sync frame.
    pub discard_presync: bool,
    /// Size of the internal per-port ring buffer (bytes).
    pub port_buf_size: usize,
}

impl Default for TpiuConfig {
    fn default() -> Self {
        Self {
            mode: TpiuMode::Formatter,
            swo_baud: 2_000_000,
            cpu_hz: 168_000_000,
            emit_sync_events: true,
            discard_presync: true,
            port_buf_size: 4096,
        }
    }
}

impl TpiuConfig {
    /// Derive the SWO prescaler value: `ceil(cpu_hz / swo_baud) - 1`.
    ///
    /// Returns 0 when `swo_baud` is zero to avoid division by zero.
    #[must_use]
    pub fn swo_prescaler(&self) -> u32 {
        if self.swo_baud == 0 {
            return 0;
        }
        let swo = u64::from(self.swo_baud);
        let divisor = self.cpu_hz.div_ceil(swo);
        u32::try_from(divisor.saturating_sub(1)).unwrap_or(u32::MAX)
    }
}

// ─── TpiuFrame ────────────────────────────────────────────────────────────────

/// A decoded 16-byte TPIU formatter frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpiuFrame {
    /// Frame sequence index (increments per 16-byte frame).
    pub frame_index: u64,
    /// ATB source ID for the first half-frame (bytes 0-7).
    pub id_first: u8,
    /// ATB source ID for the second half-frame (bytes 8-15).
    pub id_second: u8,
    /// 7 data bytes extracted from the first half-frame.
    pub data_first: [u8; 7],
    /// 7 data bytes extracted from the second half-frame.
    pub data_second: [u8; 7],
    /// Flag bit from the first half-frame header (byte 0, bit 0).
    pub flag_first: bool,
    /// Flag bit from the second half-frame header (byte 15, bit 0).
    pub flag_second: bool,
}

impl TpiuFrame {
    /// Decode a 16-byte raw TPIU formatter frame.
    ///
    /// Per the ARM `CoreSight` Architecture Specification:
    /// - Byte 0:  ID[6:0] in bits [7:1], ID-valid flag in bit 0.
    /// - Bytes 1-6: data bytes; the LSB of each data byte is stored in byte 7.
    /// - Byte 7:  aux byte; bits [7:1] hold the LSBs of bytes 1-7 in order;
    ///   bit 0 is 0 (distinguishes it from a header byte).
    /// - Bytes 8-14: data bytes; LSBs held in byte 15.
    /// - Byte 15: second half-frame header.
    /// # Errors
    ///
    /// Returns [`TpiuError::MalformedFrame`] if the auxiliary byte has an invalid flag bit.
    pub fn decode(raw: &[u8; 16], frame_index: u64) -> Result<Self, TpiuError> {
        // ── First half-frame ──────────────────────────────────────────────────
        let h0 = raw[0];
        let id_first = h0 >> 1;
        let flag_first = (h0 & 1) != 0;

        // aux byte (byte 7): bit 0 must be 0
        let aux0 = raw[7];
        if (aux0 & 1) != 0 {
            return Err(TpiuError::MalformedFrame {
                offset: 7,
                byte: aux0,
            });
        }

        let mut data_first = [0u8; 7];
        for i in 0..7 {
            let lsb = (aux0 >> (i + 1)) & 1;
            data_first[i] = (raw[1 + i] & 0xFE) | lsb;
        }

        // ── Second half-frame ─────────────────────────────────────────────────
        let h15 = raw[15];
        let id_second = h15 >> 1;
        let flag_second = (h15 & 1) != 0;

        // aux byte 15 stores LSBs for bytes 8-14 in bits [7:1].
        // Bit 0 is the flag bit (already captured in flag_second above).
        let mut data_second = [0u8; 7];
        for i in 0..7 {
            let lsb = (h15 >> (i + 1)) & 1; // bits [7:1] of h15 are LSBs for bytes 8-14
            data_second[i] = (raw[8 + i] & 0xFE) | lsb;
        }

        Ok(Self {
            frame_index,
            id_first,
            id_second,
            data_first,
            data_second,
            flag_first,
            flag_second,
        })
    }

    /// Iterate all (`atb_id`, byte) tuples emitted by this frame.
    pub fn iter_bytes(&self) -> impl Iterator<Item = (u8, u8)> + '_ {
        let first = self
            .data_first
            .iter()
            .map(move |&b| (self.id_first, b));
        let second = self
            .data_second
            .iter()
            .map(move |&b| (self.id_second, b));
        first.chain(second)
    }
}

// ─── TpiuEvent ────────────────────────────────────────────────────────────────

/// An event produced by the TPIU sink decoder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TpiuEvent {
    /// A complete TPIU frame was decoded.
    Frame(TpiuFrame),
    /// Bytes routed to a specific ATB port.
    PortData {
        /// ATB source ID (0-127 for real sources; 0 in SWO mode).
        port_id: u8,
        /// Decoded data bytes.
        data: Vec<u8>,
    },
    /// Sync pattern detected / re-aligned.
    FrameSync {
        /// Byte offset in the raw input stream where sync occurred.
        offset: usize,
        /// Whether this is the initial sync or a re-sync after loss.
        resync: bool,
    },
    /// Overflow flush cycle detected (all-zero frame).
    FlushCycle {
        /// Frame index of the flush.
        frame_index: u64,
    },
    /// Trigger cycle detected.
    TriggerCycle {
        /// Frame index.
        frame_index: u64,
    },
    /// Decoding error (non-fatal; sink continues).
    DecodeError(TpiuError),
}

// ─── PortBuffer ───────────────────────────────────────────────────────────────

/// Per-ATB-port byte buffer with overflow tracking.
#[derive(Debug, Clone)]
struct PortBuffer {
    buf: VecDeque<u8>,
    cap: usize,
    overflows: u64,
}

impl PortBuffer {
    fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap.min(1024)),
            cap,
            overflows: 0,
        }
    }

    fn push(&mut self, byte: u8) {
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
            self.overflows += 1;
        }
        self.buf.push_back(byte);
    }

    fn drain(&mut self) -> Vec<u8> {
        self.buf.drain(..).collect()
    }

    fn len(&self) -> usize {
        self.buf.len()
    }
}

// ─── TpiuSyncState ────────────────────────────────────────────────────────────

/// Internal sync state of the TPIU formatter decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncState {
    /// Searching for the 16-byte sync pattern.
    Hunting,
    /// Aligned to frame boundaries.
    Synced,
}

/// TPIU 16-byte sync pattern: 15 × 0xFF followed by 0x7F.
const TPIU_SYNC: [u8; 16] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7F,
];

// ─── TpiuSink ─────────────────────────────────────────────────────────────────

/// TPIU / SWO trace sink.
///
/// Feed raw bytes from the trace capture hardware into [`TpiuSink::ingest`] and
/// collect [`TpiuEvent`]s via the returned `Vec`.
///
/// ## Example
///
/// ```rust,ignore
/// let mut sink = TpiuSink::new(TpiuConfig::default());
/// let raw = read_trace_file("capture.tpiu");
/// let events = sink.ingest(&raw);
/// for ev in events {
///     match ev {
///         TpiuEvent::PortData { port_id, data } => process(port_id, &data),
///         _ => {}
///     }
/// }
/// ```
#[derive(Debug)]
pub struct TpiuSink {
    config: TpiuConfig,
    sync_state: SyncState,
    /// Rolling byte buffer used during sync hunting.
    hunt_buf: VecDeque<u8>,
    /// Partial frame accumulator (formatter mode).
    frame_buf: Vec<u8>,
    /// Total raw bytes consumed.
    bytes_consumed: u64,
    /// Frames decoded so far.
    frames_decoded: u64,
    /// Per-ATB-port buffers.
    port_bufs: HashMap<u8, PortBuffer>,
    /// Decode stats.
    stats: TpiuStats,
}

impl TpiuSink {
    /// Create a new TPIU/SWO sink with the given configuration.
    #[must_use]
    pub fn new(config: TpiuConfig) -> Self {
        Self {
            config,
            sync_state: SyncState::Hunting,
            hunt_buf: VecDeque::with_capacity(32),
            frame_buf: Vec::with_capacity(16),
            bytes_consumed: 0,
            frames_decoded: 0,
            port_bufs: HashMap::new(),
            stats: TpiuStats::default(),
        }
    }

    /// Return the current decode statistics.
    #[must_use]
    pub const fn stats(&self) -> &TpiuStats {
        &self.stats
    }

    /// Drain the per-port buffer for `port_id` and return accumulated bytes.
    pub fn drain_port(&mut self, port_id: u8) -> Vec<u8> {
        self.port_bufs
            .entry(port_id)
            .or_insert_with(|| PortBuffer::new(self.config.port_buf_size))
            .drain()
    }

    /// Ingest raw trace bytes.  Returns a `Vec<TpiuEvent>` of all events produced.
    pub fn ingest(&mut self, data: &[u8]) -> Vec<TpiuEvent> {
        match self.config.mode {
            TpiuMode::Swo | TpiuMode::SwoNrz => self.ingest_swo(data),
            TpiuMode::Formatter => self.ingest_formatter(data),
            TpiuMode::ParallelPort { .. } => self.ingest_parallel(data),
        }
    }

    // ── SWO / ITM raw mode ────────────────────────────────────────────────────

    fn ingest_swo(&mut self, data: &[u8]) -> Vec<TpiuEvent> {
        // In SWO mode there is no TPIU framing; all bytes go to port 0.
        let mut events = Vec::new();
        if data.is_empty() {
            return events;
        }
        self.bytes_consumed += data.len() as u64;
        self.stats.bytes_ingested += data.len() as u64;

        let port_buf = self
            .port_bufs
            .entry(0)
            .or_insert_with(|| PortBuffer::new(self.config.port_buf_size));
        for &b in data {
            port_buf.push(b);
        }
        let bytes = port_buf.drain();
        if !bytes.is_empty() {
            self.stats.bytes_routed += bytes.len() as u64;
            events.push(TpiuEvent::PortData {
                port_id: 0,
                data: bytes,
            });
        }
        events
    }

    // ── Parallel port mode ────────────────────────────────────────────────────

    fn ingest_parallel(&mut self, data: &[u8]) -> Vec<TpiuEvent> {
        // Parallel-port trace: data arrives pre-formatted, just demux by port width.
        // For simplicity treat as formatter mode in this implementation.
        self.ingest_formatter(data)
    }

    // ── Formatter mode ────────────────────────────────────────────────────────

    fn ingest_formatter(&mut self, data: &[u8]) -> Vec<TpiuEvent> {
        let mut events = Vec::new();
        let mut pos = 0usize;

        while pos < data.len() {
            match self.sync_state {
                SyncState::Hunting => {
                    let (advanced, sync_events) = self.hunt_sync(data, pos);
                    pos += advanced;
                    events.extend(sync_events);
                }
                SyncState::Synced => {
                    let needed = 16 - self.frame_buf.len();
                    let available = data.len() - pos;
                    let take = needed.min(available);
                    self.frame_buf.extend_from_slice(&data[pos..pos + take]);
                    pos += take;

                    if self.frame_buf.len() == 16 {
                        let raw: [u8; 16] = self.frame_buf.as_slice().try_into().unwrap();
                        self.frame_buf.clear();
                        let frame_events = self.decode_formatter_frame(&raw);
                        events.extend(frame_events);
                    }
                }
            }
        }

        self.bytes_consumed += data.len() as u64;
        self.stats.bytes_ingested += data.len() as u64;
        events
    }

    /// Hunt for the TPIU sync pattern.  Returns (`bytes_consumed`, events).
    fn hunt_sync(&mut self, data: &[u8], start: usize) -> (usize, Vec<TpiuEvent>) {
        let mut events = Vec::new();
        let mut consumed = 0;

        for &b in &data[start..] {
            consumed += 1;
            self.hunt_buf.push_back(b);
            if self.hunt_buf.len() > 16 {
                self.hunt_buf.pop_front();
            }
            if self.hunt_buf.len() == 16 {
                let buf: Vec<u8> = self.hunt_buf.iter().copied().collect();
                if buf == TPIU_SYNC {
                    let offset = usize::try_from(self.bytes_consumed.saturating_add(consumed as u64)).unwrap_or(usize::MAX);
                    self.sync_state = SyncState::Synced;
                    self.hunt_buf.clear();
                    self.frame_buf.clear();
                    self.stats.sync_count += 1;

                    if self.config.emit_sync_events {
                        events.push(TpiuEvent::FrameSync {
                            offset,
                            resync: self.stats.sync_count > 1,
                        });
                    }
                    break;
                }
            }
        }
        (consumed, events)
    }

    /// Decode a single 16-byte TPIU formatter frame.
    fn decode_formatter_frame(&mut self, raw: &[u8; 16]) -> Vec<TpiuEvent> {
        let mut events = Vec::new();
        self.frames_decoded += 1;
        self.stats.frames_decoded += 1;

        // Detect flush cycle (all 0x00) or trigger cycle (0xFF bytes).
        if raw == &[0x00u8; 16] {
            events.push(TpiuEvent::FlushCycle {
                frame_index: self.frames_decoded,
            });
            return events;
        }
        if raw == &[0xFFu8; 16] {
            events.push(TpiuEvent::TriggerCycle {
                frame_index: self.frames_decoded,
            });
            return events;
        }
        // Detect re-sync inside data stream.
        if raw == &TPIU_SYNC {
            self.stats.sync_count += 1;
            if self.config.emit_sync_events {
                events.push(TpiuEvent::FrameSync {
                    offset: usize::try_from(self.bytes_consumed).unwrap_or(usize::MAX),
                    resync: true,
                });
            }
            return events;
        }

        match TpiuFrame::decode(raw, self.frames_decoded) {
            Ok(frame) => {
                // Route bytes to per-port buffers.
                let cap = self.config.port_buf_size;
                let mut routed: HashMap<u8, Vec<u8>> = HashMap::new();

                for (id, byte) in frame.iter_bytes() {
                    let pb = self
                        .port_bufs
                        .entry(id)
                        .or_insert_with(|| PortBuffer::new(cap));
                    pb.push(byte);
                    routed.entry(id).or_default().push(byte);
                }

                self.stats.bytes_routed += 14; // 7 + 7 data bytes per frame

                // Emit PortData events grouped by port.
                for (port_id, data) in routed {
                    events.push(TpiuEvent::PortData { port_id, data });
                }

                if self.config.emit_sync_events {
                    events.push(TpiuEvent::Frame(frame));
                }
            }
            Err(e) => {
                self.stats.frame_errors += 1;
                // Attempt re-sync on malformed frame.
                self.sync_state = SyncState::Hunting;
                events.push(TpiuEvent::DecodeError(e));
            }
        }
        events
    }

    /// Force a re-sync (e.g., after detecting data loss).
    pub fn reset_sync(&mut self) {
        self.sync_state = SyncState::Hunting;
        self.hunt_buf.clear();
        self.frame_buf.clear();
        self.stats.sync_lost += 1;
    }

    /// Return the number of bytes available in a port's buffer without draining.
    #[must_use]
    pub fn port_pending(&self, port_id: u8) -> usize {
        self.port_bufs
            .get(&port_id)
            .map_or(0, PortBuffer::len)
    }

    /// List all ATB port IDs that have received data.
    #[must_use]
    pub fn active_ports(&self) -> Vec<u8> {
        let mut ids: Vec<u8> = self.port_bufs.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

// ─── TpiuStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for a TPIU sink session.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TpiuStats {
    /// Total raw bytes ingested.
    pub bytes_ingested: u64,
    /// Total data bytes routed to port buffers.
    pub bytes_routed: u64,
    /// Number of TPIU sync patterns detected (including re-syncs).
    pub sync_count: u64,
    /// Number of times sync was lost.
    pub sync_lost: u64,
    /// Number of complete 16-byte frames decoded.
    pub frames_decoded: u64,
    /// Number of frames that produced a decode error.
    pub frame_errors: u64,
    /// Number of flush cycles detected.
    pub flush_cycles: u64,
    /// Number of trigger cycles detected.
    pub trigger_cycles: u64,
}

impl TpiuStats {
    /// Bytes lost to frame errors as a fraction of bytes ingested.
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.frames_decoded == 0 {
            return 0.0;
        }
        let ppm = u128::from(self.frame_errors) * 1_000_000 / u128::from(self.frames_decoded);
        f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
    }

    /// Fraction of ingested bytes successfully routed to ports.
    #[must_use]
    pub fn routing_efficiency(&self) -> f64 {
        if self.bytes_ingested == 0 {
            return 0.0;
        }
        let ppm = u128::from(self.bytes_routed) * 1_000_000 / u128::from(self.bytes_ingested);
        f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
    }
}

// ─── SwoDecoder ───────────────────────────────────────────────────────────────

/// State machine for ITM/DWT packet decode over a SWO byte stream.
///
/// Handles:
/// - Instrumentation packets (stimulus ports 0-31)
/// - Hardware (DWT) source packets
/// - Protocol synchronization packets (all-zero followed by 0x80)
/// - Overflow packets (0x70)
/// - Local timestamp packets
/// - Extension packets
#[derive(Debug)]
pub struct SwoDecoder {
    state: SwoState,
    /// Byte accumulator for multi-byte packets.
    acc: Vec<u8>,
    /// Current source type being accumulated.
    pending: Option<SwoPacketHeader>,
    /// Decoded events.
    events: Vec<SwoPacket>,
    /// Statistics.
    stats: SwoStats,
}

/// Internal state of the ITM/SWO decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwoState {
    /// Waiting for the first byte of a new packet.
    Idle,
    /// Accumulating a multi-byte payload.
    Collecting,
    /// Waiting for the sync terminator (0x80) after all-zero sync bytes.
    SyncTerminator,
}

/// Decoded header of an ITM/DWT packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SwoPacketHeader {
    kind: SwoPacketKind,
    payload_len: usize,
}

/// Packet kind for ITM/DWT/protocol packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwoPacketKind {
    /// Instrumentation (stimulus) port write.
    Instrumentation {
        /// Stimulus port number (0-31).
        port: u8,
    },
    /// Hardware (DWT) source packet.
    Hardware {
        /// DWT discriminator ID.
        disc_id: u8,
    },
    /// Overflow (0x70): some events were lost.
    Overflow,
    /// Local timestamp.
    LocalTimestamp,
    /// Global timestamp type 1 (48-bit system timestamp).
    GlobalTimestamp1,
    /// Global timestamp type 2 (64-bit extension).
    GlobalTimestamp2,
    /// Extension packet.
    Extension {
        /// Source bit.
        src: u8,
    },
    /// Synchronization (all-zero + 0x80 terminator).
    Synchronization,
}

/// A fully decoded ITM/DWT/protocol packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwoPacket {
    /// Packet kind.
    pub kind: SwoPacketKind,
    /// Raw payload bytes (may be empty).
    pub payload: Vec<u8>,
}

impl SwoPacket {
    /// Decode a 1-byte, 2-byte, or 4-byte instrumentation value.
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        match self.payload.len() {
            1 => Some(u32::from(self.payload[0])),
            2 => Some(u32::from(u16::from_le_bytes([self.payload[0], self.payload[1]]))),
            4 => Some(u32::from_le_bytes([
                self.payload[0],
                self.payload[1],
                self.payload[2],
                self.payload[3],
            ])),
            _ => None,
        }
    }

    /// Interpret an instrumentation payload as a UTF-8 character sequence.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
}

/// Statistics for the SWO decoder.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SwoStats {
    /// Total bytes processed.
    pub bytes_processed: u64,
    /// Instrumentation packets decoded.
    pub instrumentation_packets: u64,
    /// Hardware (DWT) packets decoded.
    pub hardware_packets: u64,
    /// Overflow events detected.
    pub overflow_events: u64,
    /// Timestamp packets decoded.
    pub timestamp_packets: u64,
    /// Synchronization packets detected.
    pub sync_packets: u64,
    /// Bytes discarded due to framing errors.
    pub framing_errors: u64,
}

impl SwoDecoder {
    /// Create a new SWO / ITM packet decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SwoState::Idle,
            acc: Vec::with_capacity(4),
            pending: None,
            events: Vec::new(),
            stats: SwoStats::default(),
        }
    }

    /// Return decode statistics.
    #[must_use]
    pub const fn stats(&self) -> &SwoStats {
        &self.stats
    }

    /// Drain all pending decoded packets.
    pub fn drain_packets(&mut self) -> Vec<SwoPacket> {
        std::mem::take(&mut self.events)
    }

    /// Feed raw SWO bytes into the decoder.  Decoded packets accumulate
    /// internally; call [`Self::drain_packets`] to retrieve them.
    pub fn feed(&mut self, data: &[u8]) {
        self.stats.bytes_processed += u64::try_from(data.len()).unwrap_or(u64::MAX);
        for &b in data {
            self.process_byte(b);
        }
    }

    fn process_byte(&mut self, b: u8) {
        match self.state {
            SwoState::Idle => self.decode_header(b),
            SwoState::Collecting => self.collect_payload(b),
            SwoState::SyncTerminator => {
                if b == 0x80 {
                    // End of sync sequence.
                    self.stats.sync_packets += 1;
                    self.events.push(SwoPacket {
                        kind: SwoPacketKind::Synchronization,
                        payload: vec![],
                    });
                } else if b == 0x00 {
                    // Still in sync run.
                } else {
                    // Lost sync: treat as new packet header.
                    self.state = SwoState::Idle;
                    self.decode_header(b);
                }
            }
        }
    }

    fn decode_header(&mut self, b: u8) {
        // Synchronization: leading 0x00 byte.
        if b == 0x00 {
            self.state = SwoState::SyncTerminator;
            return;
        }

        // Overflow: 0x70.
        if b == 0x70 {
            self.stats.overflow_events += 1;
            self.events.push(SwoPacket {
                kind: SwoPacketKind::Overflow,
                payload: vec![],
            });
            return;
        }

        // Local timestamp type 1: 0b1_xx0_0000 (bits[3:0] == 0b0000, bit 7 == 1).
        if b.trailing_zeros() >= 4 && b & 0x80 != 0 {
            let cont = (b & 0x80) != 0;
            if cont {
                // Multi-byte timestamp: 0b_1_ttt_0000 where ttt != 0.
                let payload_len = 1; // will read continuation bytes
                self.pending = Some(SwoPacketHeader {
                    kind: SwoPacketKind::LocalTimestamp,
                    payload_len,
                });
                self.acc.clear();
                self.state = SwoState::Collecting;
                return;
            }
        }

        // Local timestamp type 2: 0b0_xxx_0000 (no continuation).
        if b & 0x8F == 0x00 {
            // ts[3:1] in bits [3:1] — but 0x00 is sync, handled above.
            self.stats.timestamp_packets += 1;
            self.events.push(SwoPacket {
                kind: SwoPacketKind::LocalTimestamp,
                payload: vec![b],
            });
            return;
        }

        // Global timestamp type 1: 0b1001_0100.
        if b == 0x94 {
            self.pending = Some(SwoPacketHeader {
                kind: SwoPacketKind::GlobalTimestamp1,
                payload_len: 4,
            });
            self.acc.clear();
            self.state = SwoState::Collecting;
            return;
        }

        // Global timestamp type 2: 0b1011_0100.
        if b == 0xB4 {
            self.pending = Some(SwoPacketHeader {
                kind: SwoPacketKind::GlobalTimestamp2,
                payload_len: 8,
            });
            self.acc.clear();
            self.state = SwoState::Collecting;
            return;
        }

        // Extension packet: 0b0_xxx_1000 or 0b0_xxx_1001.
        if b & 0x0F == 0x08 || b & 0x0F == 0x09 {
            let src = (b >> 3) & 0x1F;
            if (b & 0x80) != 0 {
                // Multi-byte extension.
                self.pending = Some(SwoPacketHeader {
                    kind: SwoPacketKind::Extension { src },
                    payload_len: 1,
                });
                self.acc.clear();
                self.state = SwoState::Collecting;
            } else {
                self.events.push(SwoPacket {
                    kind: SwoPacketKind::Extension { src },
                    payload: vec![],
                });
            }
            return;
        }

        // Instrumentation or hardware source packet.
        // Bits [1:0]: payload size (0b00 = reserved, 0b01 = 1B, 0b10 = 2B, 0b11 = 4B).
        let size_bits = b & 0x03;
        if size_bits == 0 {
            // Reserved / ignored.
            self.stats.framing_errors += 1;
            return;
        }
        let payload_len = 1usize << (size_bits - 1); // 1, 2, or 4

        // Per ITM/SWO: source bits [7:3]. Source ID 0 = software/instrumentation;
        // any nonzero discriminator = hardware (DWT) source packet.
        let src = (b >> 3) & 0x1F;
        if src == 0 {
            // Instrumentation packet on port 0 (the only software port for
            // the simple software-source path; higher ports use other headers).
            self.pending = Some(SwoPacketHeader {
                kind: SwoPacketKind::Instrumentation { port: 0 },
                payload_len,
            });
        } else {
            // Hardware source packet.
            self.pending = Some(SwoPacketHeader {
                kind: SwoPacketKind::Hardware { disc_id: src },
                payload_len,
            });
        }
        self.acc.clear();
        self.state = SwoState::Collecting;
    }

    fn collect_payload(&mut self, b: u8) {
        let Some(hdr) = self.pending else {
            self.state = SwoState::Idle;
            return;
        };

        // For variable-length timestamp/extension packets, continuation bit drives length.
        let is_variable = matches!(
            hdr.kind,
            SwoPacketKind::LocalTimestamp | SwoPacketKind::Extension { .. }
        );

        self.acc.push(b);

        let done = if is_variable {
            // Continuation bit 7 == 0 means last byte.
            (b & 0x80) == 0
        } else {
            self.acc.len() >= hdr.payload_len
        };

        if done {
            let pkt = SwoPacket {
                kind: hdr.kind,
                payload: std::mem::take(&mut self.acc),
            };
            match hdr.kind {
                SwoPacketKind::Instrumentation { .. } => self.stats.instrumentation_packets += 1,
                SwoPacketKind::Hardware { .. } => self.stats.hardware_packets += 1,
                SwoPacketKind::LocalTimestamp
                | SwoPacketKind::GlobalTimestamp1
                | SwoPacketKind::GlobalTimestamp2 => self.stats.timestamp_packets += 1,
                _ => {}
            }
            self.events.push(pkt);
            self.pending = None;
            self.state = SwoState::Idle;
        }
    }
}

impl Default for SwoDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PortDemux ────────────────────────────────────────────────────────────────

/// Routes ATB port data from a [`TpiuSink`] to multiple [`SwoDecoder`] instances.
///
/// Useful when an FPGA or debug probe multiplexes several ITM streams (one per
/// CPU core) onto a single TPIU trace port.
#[derive(Debug)]
pub struct PortDemux {
    sink: TpiuSink,
    decoders: HashMap<u8, SwoDecoder>,
}

impl PortDemux {
    /// Create a new demultiplexer backed by the given TPIU sink.
    #[must_use]
    pub fn new(config: TpiuConfig) -> Self {
        Self {
            sink: TpiuSink::new(config),
            decoders: HashMap::new(),
        }
    }

    /// Feed raw TPIU bytes.  Returns a map of port → decoded ITM packets.
    pub fn feed(&mut self, data: &[u8]) -> HashMap<u8, Vec<SwoPacket>> {
        let events = self.sink.ingest(data);
        let mut out: HashMap<u8, Vec<SwoPacket>> = HashMap::new();

        for event in events {
            if let TpiuEvent::PortData { port_id, data } = event {
                let dec = self
                    .decoders
                    .entry(port_id)
                    .or_default();
                dec.feed(&data);
                let pkts = dec.drain_packets();
                if !pkts.is_empty() {
                    out.entry(port_id).or_default().extend(pkts);
                }
            }
        }
        out
    }

    /// Return the underlying [`TpiuSink`].
    #[must_use]
    pub const fn sink(&self) -> &TpiuSink {
        &self.sink
    }

    /// Return the SWO decoder for a specific port.
    #[must_use]
    pub fn decoder_for(&self, port_id: u8) -> Option<&SwoDecoder> {
        self.decoders.get(&port_id)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TpiuConfig ────────────────────────────────────────────────────────────

    #[test]
    fn test_swo_prescaler() {
        let cfg = TpiuConfig {
            cpu_hz: 168_000_000,
            swo_baud: 2_000_000,
            ..Default::default()
        };
        // ceil(168e6 / 2e6) - 1 = ceil(84) - 1 = 83
        assert_eq!(cfg.swo_prescaler(), 83);
    }

    #[test]
    fn test_swo_prescaler_exact() {
        let cfg = TpiuConfig {
            cpu_hz: 72_000_000,
            swo_baud: 9_000_000,
            ..Default::default()
        };
        // 72/9 = 8 exactly → prescaler = 7
        assert_eq!(cfg.swo_prescaler(), 7);
    }

    // ── TpiuFrame ─────────────────────────────────────────────────────────────

    #[test]
    fn test_frame_decode_all_zeros_is_flush() {
        let raw = [0u8; 16];
        let mut sink = TpiuSink::new(TpiuConfig {
            emit_sync_events: false,
            ..Default::default()
        });
        // Manually call decode_formatter_frame.
        let events = sink.decode_formatter_frame(&raw);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], TpiuEvent::FlushCycle { .. }));
    }

    #[test]
    fn test_frame_decode_all_ff_is_trigger() {
        let raw = [0xFF_u8; 16];
        let mut sink = TpiuSink::new(TpiuConfig {
            emit_sync_events: false,
            ..Default::default()
        });
        let events = sink.decode_formatter_frame(&raw);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], TpiuEvent::TriggerCycle { .. }));
    }

    #[test]
    fn test_frame_sync_pattern_detected() {
        let mut sink = TpiuSink::new(TpiuConfig {
            emit_sync_events: true,
            discard_presync: true,
            ..Default::default()
        });
        let events = sink.ingest(&TPIU_SYNC);
        let has_sync = events
            .iter()
            .any(|e| matches!(e, TpiuEvent::FrameSync { .. }));
        assert!(has_sync, "sync pattern must produce FrameSync event");
    }

    #[test]
    fn test_frame_sync_followed_by_data() {
        let mut sink = TpiuSink::new(TpiuConfig {
            emit_sync_events: true,
            discard_presync: true,
            ..Default::default()
        });
        // Feed sync pattern then a flush frame.
        let mut data = TPIU_SYNC.to_vec();
        data.extend_from_slice(&[0x00u8; 16]);
        let events = sink.ingest(&data);
        let has_sync = events
            .iter()
            .any(|e| matches!(e, TpiuEvent::FrameSync { .. }));
        let has_flush = events
            .iter()
            .any(|e| matches!(e, TpiuEvent::FlushCycle { .. }));
        assert!(has_sync);
        assert!(has_flush);
    }

    // ── SwoDecoder ────────────────────────────────────────────────────────────

    #[test]
    fn test_swo_overflow_packet() {
        let mut dec = SwoDecoder::new();
        dec.feed(&[0x70]);
        let pkts = dec.drain_packets();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, SwoPacketKind::Overflow);
        assert_eq!(dec.stats().overflow_events, 1);
    }

    #[test]
    fn test_swo_sync_packet() {
        let mut dec = SwoDecoder::new();
        // Sync = 5 × 0x00 + 0x80
        dec.feed(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
        let pkts = dec.drain_packets();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, SwoPacketKind::Synchronization);
        assert_eq!(dec.stats().sync_packets, 1);
    }

    #[test]
    fn test_swo_instrumentation_1byte() {
        let mut dec = SwoDecoder::new();
        // Header: port=0, size=1byte → 0b000_00_001 = 0x01
        dec.feed(&[0x01, 0x41]); // payload 'A'
        let pkts = dec.drain_packets();
        assert_eq!(pkts.len(), 1);
        assert_eq!(
            pkts[0].kind,
            SwoPacketKind::Instrumentation { port: 0 }
        );
        assert_eq!(pkts[0].as_u32(), Some(0x41));
        assert_eq!(dec.stats().instrumentation_packets, 1);
    }

    #[test]
    fn test_swo_instrumentation_4byte() {
        let mut dec = SwoDecoder::new();
        // Header: port=0, size=4bytes → 0b000_00_011 = 0x03
        dec.feed(&[0x03, 0xDE, 0xAD, 0xBE, 0xEF]);
        let pkts = dec.drain_packets();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].as_u32(), Some(0xEFBEADDE));
    }

    #[test]
    fn test_swo_hardware_packet() {
        let mut dec = SwoDecoder::new();
        // Hardware, disc_id=1, 2-byte payload: 0b000_00100_10 → bits: 0x26
        // disc_id=4 in bits [7:3]=0b00100, size bits=0b10 → 0x22
        dec.feed(&[0x22, 0x00, 0x10]);
        let pkts = dec.drain_packets();
        assert_eq!(pkts.len(), 1);
        assert!(matches!(pkts[0].kind, SwoPacketKind::Hardware { .. }));
        assert_eq!(dec.stats().hardware_packets, 1);
    }

    #[test]
    fn test_swo_multiple_packets() {
        let mut dec = SwoDecoder::new();
        // Two 1-byte instrumentation packets.
        dec.feed(&[0x01, 0x41, 0x01, 0x42]);
        let pkts = dec.drain_packets();
        assert_eq!(pkts.len(), 2);
        assert_eq!(dec.stats().instrumentation_packets, 2);
    }

    #[test]
    fn test_swo_as_str() {
        let pkt = SwoPacket {
            kind: SwoPacketKind::Instrumentation { port: 0 },
            payload: b"Hi".to_vec(),
        };
        assert_eq!(pkt.as_str(), Some("Hi"));
    }

    // ── PortBuffer ────────────────────────────────────────────────────────────

    #[test]
    fn test_port_buffer_overflow() {
        let mut pb = PortBuffer::new(4);
        for i in 0u8..8 {
            pb.push(i);
        }
        assert_eq!(pb.overflows, 4);
        let data = pb.drain();
        // Only last 4 bytes remain.
        assert_eq!(data, vec![4, 5, 6, 7]);
    }

    // ── TpiuSink SWO mode ─────────────────────────────────────────────────────

    #[test]
    fn test_sink_swo_mode() {
        let cfg = TpiuConfig {
            mode: TpiuMode::Swo,
            ..Default::default()
        };
        let mut sink = TpiuSink::new(cfg);
        let events = sink.ingest(&[0x01, 0x02, 0x03]);
        let has_port_data = events
            .iter()
            .any(|e| matches!(e, TpiuEvent::PortData { port_id: 0, .. }));
        assert!(has_port_data);
        assert_eq!(sink.stats().bytes_ingested, 3);
    }

    #[test]
    fn test_active_ports_empty() {
        let sink = TpiuSink::new(TpiuConfig::default());
        assert!(sink.active_ports().is_empty());
    }

    #[test]
    fn test_reset_sync() {
        let mut sink = TpiuSink::new(TpiuConfig::default());
        sink.ingest(&TPIU_SYNC);
        assert_eq!(sink.sync_state, SyncState::Synced);
        sink.reset_sync();
        assert_eq!(sink.sync_state, SyncState::Hunting);
        assert_eq!(sink.stats().sync_lost, 1);
    }

    // ── PortDemux ─────────────────────────────────────────────────────────────

    #[test]
    fn test_port_demux_swo_mode() {
        let cfg = TpiuConfig {
            mode: TpiuMode::Swo,
            ..Default::default()
        };
        let mut demux = PortDemux::new(cfg);
        // Feed an overflow packet.
        let out = demux.feed(&[0x70]);
        let pkts = out.get(&0).map(Vec::as_slice).unwrap_or_default();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, SwoPacketKind::Overflow);
    }

    #[test]
    fn test_tpiu_stats_error_rate_zero() {
        let stats = TpiuStats::default();
        assert_eq!(stats.error_rate(), 0.0);
        assert_eq!(stats.routing_efficiency(), 0.0);
    }

    #[test]
    fn test_tpiu_stats_error_rate() {
        let stats = TpiuStats {
            frames_decoded: 100,
            frame_errors: 5,
            bytes_ingested: 1600,
            bytes_routed: 1400,
            ..Default::default()
        };
        assert!((stats.error_rate() - 0.05).abs() < 1e-9);
        assert!((stats.routing_efficiency() - 0.875).abs() < 1e-9);
    }
}
