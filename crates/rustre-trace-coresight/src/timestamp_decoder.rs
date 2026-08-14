//! `CoreSight` timestamp packet decoder.
//!
//! `CoreSight` ETM4/ETE uses variable-length ULEB128 timestamp packets to encode
//! a monotonically increasing 64-bit counter.  This module accumulates them
//! into a [`CsTimestamp`] and exposes alignment/delta utilities.

// ── CsTimestamp ───────────────────────────────────────────────────────────────

/// A 64-bit `CoreSight` timestamp counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct CsTimestamp(pub u64);

impl CsTimestamp {
    /// Construct from a raw counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw counter value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Return the delta from `earlier`.  Wraps on overflow.
    #[must_use]
    pub const fn delta_from(self, earlier: Self) -> u64 {
        self.0.wrapping_sub(earlier.0)
    }

    /// Return `true` if this timestamp is strictly later than `other`.
    #[must_use]
    pub const fn is_after(self, other: Self) -> bool {
        self.0 > other.0
    }
}

impl std::fmt::Display for CsTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ts:{}", self.0)
    }
}

impl From<u64> for CsTimestamp {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

// ── TimestampAlignment ────────────────────────────────────────────────────────

/// How a timestamp update should be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampAlignment {
    /// Full 64-bit replacement.
    Full,
    /// Partial update — only the low `bits` bits are valid.
    Partial {
        /// Number of low-order bits to update.
        bits: u8,
    },
}

// ── TimestampPacket ───────────────────────────────────────────────────────────

/// A decoded `CoreSight` timestamp packet.
#[derive(Debug, Clone)]
pub struct TimestampPacket {
    /// Raw value carried by the packet.
    pub raw_value: u64,
    /// Number of valid low-order bits (`7 * n` for an `n`-byte ULEB128 packet).
    pub valid_bits: u8,
    /// Byte offset in the trace stream where this packet starts.
    pub byte_offset: usize,
}

impl TimestampPacket {
    /// Construct a new timestamp packet.
    #[must_use]
    pub const fn new(raw_value: u64, valid_bits: u8, byte_offset: usize) -> Self {
        Self {
            raw_value,
            valid_bits,
            byte_offset,
        }
    }

    /// Return the alignment mode implied by `valid_bits`.
    #[must_use]
    pub const fn alignment(&self) -> TimestampAlignment {
        if self.valid_bits >= 64 {
            TimestampAlignment::Full
        } else {
            TimestampAlignment::Partial {
                bits: self.valid_bits,
            }
        }
    }
}

// ── TimestampDecoder ──────────────────────────────────────────────────────────

/// Accumulates `CoreSight` timestamp packets into a running 64-bit counter.
///
/// The decoder maintains the last known timestamp and applies each packet's
/// update (full replacement or low-bits partial update).
pub struct TimestampDecoder {
    /// Most recently committed timestamp value.
    pub current: CsTimestamp,
    /// All decoded packets, in arrival order.
    pub packets: Vec<TimestampPacket>,
    /// Count of partial updates applied.
    pub partial_updates: u64,
    /// Count of full updates applied.
    pub full_updates: u64,
}

impl TimestampDecoder {
    /// Create a new decoder with an initial timestamp of 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current: CsTimestamp::new(0),
            packets: Vec::new(),
            partial_updates: 0,
            full_updates: 0,
        }
    }

    /// Create a decoder with a known starting timestamp (for mid-stream attach).
    #[must_use]
    pub const fn with_base(base: CsTimestamp) -> Self {
        Self {
            current: base,
            packets: Vec::new(),
            partial_updates: 0,
            full_updates: 0,
        }
    }

    /// Decode a ULEB128 timestamp packet from `data` at `offset`.
    ///
    /// Returns `(packet, bytes_consumed)` or `None` if the buffer is exhausted.
    #[must_use]
    pub fn decode_packet(data: &[u8], offset: usize) -> Option<(TimestampPacket, usize)> {
        if offset >= data.len() {
            return None;
        }
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        let mut consumed = 0usize;
        loop {
            let pos = offset + consumed;
            if pos >= data.len() {
                return None; // truncated
            }
            let byte = data[pos];
            consumed += 1;
            value |= u64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                break; // overflow guard
            }
        }
        let valid_bits = shift.min(64) as u8;
        Some((TimestampPacket::new(value, valid_bits, offset), consumed))
    }

    /// Apply a [`TimestampPacket`] to update the current timestamp.
    pub fn apply(&mut self, pkt: TimestampPacket) {
        match pkt.alignment() {
            TimestampAlignment::Full => {
                self.current = CsTimestamp::new(pkt.raw_value);
                self.full_updates += 1;
            }
            TimestampAlignment::Partial { bits } => {
                let mask = if bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << bits) - 1
                };
                let new_val = (self.current.0 & !mask) | (pkt.raw_value & mask);
                self.current = CsTimestamp::new(new_val);
                self.partial_updates += 1;
            }
        }
        self.packets.push(pkt);
    }

    /// Decode and apply all ULEB128 timestamp packets from `data`.
    ///
    /// This is a simple linear scan that assumes every byte is the start of a
    /// new ULEB128 sequence (suitable for a pure-timestamp test stream).
    pub fn feed_raw(&mut self, data: &[u8]) {
        let mut off = 0;
        while let Some((pkt, consumed)) = Self::decode_packet(data, off) {
            self.apply(pkt);
            off += consumed;
        }
    }

    /// Return the total number of packets accumulated.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Reset the decoder to its zero state.
    pub fn reset(&mut self) {
        self.current = CsTimestamp::new(0);
        self.packets.clear();
        self.partial_updates = 0;
        self.full_updates = 0;
    }

    /// Return delta (in counter ticks) between consecutive packets `i` and `i+1`.
    ///
    /// Returns `None` if there are fewer than 2 packets or `i+1` is out of range.
    #[must_use]
    pub fn inter_packet_delta(&self, i: usize) -> Option<u64> {
        if i + 1 >= self.packets.len() {
            return None;
        }
        Some(
            self.packets[i + 1]
                .raw_value
                .wrapping_sub(self.packets[i].raw_value),
        )
    }
}

impl Default for TimestampDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cs_timestamp_value_and_display() {
        let ts = CsTimestamp::new(0x1234_5678_9ABC_DEF0);
        assert_eq!(ts.value(), 0x1234_5678_9ABC_DEF0);
        let s = ts.to_string();
        assert!(s.starts_with("ts:"));
    }

    #[test]
    fn test_cs_timestamp_delta_from() {
        let a = CsTimestamp::new(100);
        let b = CsTimestamp::new(300);
        assert_eq!(b.delta_from(a), 200);
    }

    #[test]
    fn test_cs_timestamp_is_after() {
        let a = CsTimestamp::new(50);
        let b = CsTimestamp::new(100);
        assert!(b.is_after(a));
        assert!(!a.is_after(b));
    }

    #[test]
    fn test_decode_single_byte_uleb128() {
        // Single byte: 0x7F -> value = 127, 7 valid bits
        let data = [0x7F_u8];
        let (pkt, consumed) = TimestampDecoder::decode_packet(&data, 0).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(pkt.raw_value, 127);
        assert_eq!(pkt.valid_bits, 7);
    }

    #[test]
    fn test_decode_multibyte_uleb128() {
        // Two bytes: 0x80, 0x01 -> value = 128
        let data = [0x80_u8, 0x01];
        let (pkt, consumed) = TimestampDecoder::decode_packet(&data, 0).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(pkt.raw_value, 128);
        assert_eq!(pkt.valid_bits, 14);
    }

    #[test]
    fn test_decoder_apply_full_update() {
        let mut dec = TimestampDecoder::new();
        let pkt = TimestampPacket::new(0xDEAD_BEEF, 64, 0);
        dec.apply(pkt);
        assert_eq!(dec.current.value(), 0xDEAD_BEEF);
        assert_eq!(dec.full_updates, 1);
    }

    #[test]
    fn test_decoder_apply_partial_update() {
        let mut dec = TimestampDecoder::with_base(CsTimestamp::new(0xFFFF_FFFF_0000_0000));
        // partial update: 7 bits, value = 0x55
        let pkt = TimestampPacket::new(0x55, 7, 0);
        dec.apply(pkt);
        // low 7 bits of current become 0x55; upper bits unchanged
        let expected = (0xFFFF_FFFF_0000_0000u64 & !0x7F) | 0x55;
        assert_eq!(dec.current.value(), expected);
        assert_eq!(dec.partial_updates, 1);
    }

    #[test]
    fn test_decoder_reset() {
        let mut dec = TimestampDecoder::new();
        let pkt = TimestampPacket::new(999, 64, 0);
        dec.apply(pkt);
        dec.reset();
        assert_eq!(dec.current.value(), 0);
        assert_eq!(dec.packet_count(), 0);
    }

    #[test]
    fn test_timestamp_alignment_full_vs_partial() {
        let full_pkt = TimestampPacket::new(0, 64, 0);
        assert_eq!(full_pkt.alignment(), TimestampAlignment::Full);

        let partial_pkt = TimestampPacket::new(0, 7, 0);
        assert_eq!(
            partial_pkt.alignment(),
            TimestampAlignment::Partial { bits: 7 }
        );
    }

    #[test]
    fn test_feed_raw_sequence() {
        let mut dec = TimestampDecoder::new();
        // Three single-byte ULEB128 values: 1, 2, 3
        dec.feed_raw(&[0x01, 0x02, 0x03]);
        // Last applied value should be 3
        assert_eq!(dec.current.value(), 3);
        assert_eq!(dec.packet_count(), 3);
    }
}
