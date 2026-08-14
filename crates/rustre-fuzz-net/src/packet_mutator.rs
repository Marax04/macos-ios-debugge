/// Packet-level mutators for network fuzzing.
///
/// Provides bit-flip, byte substitution, length-field corruption,
/// checksum corruption, field-boundary mutations, and protocol-specific
/// mutations (HTTP header injection, DNS label overflow, TLS version confusion).

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Mutation primitives
// ---------------------------------------------------------------------------

/// Flip the bit at `bit_offset` (0 = MSB of byte 0).
#[must_use]
pub fn flip_bit(data: &[u8], bit_offset: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    let byte_idx = bit_offset / 8;
    let bit_idx = 7 - (bit_offset % 8);
    if byte_idx < out.len() {
        out[byte_idx] ^= 1 << bit_idx;
    }
    out
}

/// Replace the byte at `offset` with `value`.
#[must_use]
pub fn substitute_byte(data: &[u8], offset: usize, value: u8) -> Vec<u8> {
    let mut out = data.to_vec();
    if offset < out.len() {
        out[offset] = value;
    }
    out
}

/// Insert `extra` bytes at `offset`.
#[must_use]
pub fn insert_bytes(data: &[u8], offset: usize, extra: &[u8]) -> Vec<u8> {
    let offset = offset.min(data.len());
    let mut out = Vec::with_capacity(data.len() + extra.len());
    out.extend_from_slice(&data[..offset]);
    out.extend_from_slice(extra);
    out.extend_from_slice(&data[offset..]);
    out
}

/// Delete `count` bytes starting at `offset`.
#[must_use]
pub fn delete_bytes(data: &[u8], offset: usize, count: usize) -> Vec<u8> {
    if offset >= data.len() {
        return data.to_vec();
    }
    let end = (offset + count).min(data.len());
    let mut out = Vec::with_capacity(data.len() - (end - offset));
    out.extend_from_slice(&data[..offset]);
    out.extend_from_slice(&data[end..]);
    out
}

/// Overwrite bytes in `range` with `fill`.
#[must_use]
pub fn overwrite_range(data: &[u8], offset: usize, fill: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (i, &b) in fill.iter().enumerate() {
        let idx = offset + i;
        if idx < out.len() {
            out[idx] = b;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// FieldMutation — describes a targeted mutation on a named field
// ---------------------------------------------------------------------------

/// The concrete operation to apply to a field.
#[derive(Debug, Clone)]
pub enum MutationOp {
    /// XOR every byte with a mask.
    XorMask(u8),
    /// Replace the field entirely.
    Replace(Vec<u8>),
    /// Overflow: extend the field by `extra` bytes.
    Overflow(Vec<u8>),
    /// Set to an "interesting" integer value (encoded big-endian).
    InterestingInt(u64),
    /// Randomise all bytes using the given seed.
    RandomFill(u64),
    /// Truncate the field to `new_len` bytes.
    Truncate(usize),
    /// Duplicate the field's content n times.
    Repeat(usize),
}

/// A mutation targeting one named field within a packet.
#[derive(Debug, Clone)]
pub struct FieldMutation {
    pub field_name: String,
    pub byte_offset: usize,
    pub field_len: usize,
    pub op: MutationOp,
}

impl FieldMutation {
    pub fn new(field_name: impl Into<String>, offset: usize, len: usize, op: MutationOp) -> Self {
        Self {
            field_name: field_name.into(),
            byte_offset: offset,
            field_len: len,
            op,
        }
    }

    /// Apply this mutation to `data` and return a new buffer.
    #[must_use]
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        match &self.op {
            MutationOp::XorMask(mask) => {
                let mut out = data.to_vec();
                for i in self.byte_offset..(self.byte_offset + self.field_len).min(data.len()) {
                    out[i] ^= mask;
                }
                out
            }
            MutationOp::Replace(bytes) => {
                overwrite_range(data, self.byte_offset, bytes)
            }
            MutationOp::Overflow(extra) => {
                let insert_at = (self.byte_offset + self.field_len).min(data.len());
                insert_bytes(data, insert_at, extra)
            }
            MutationOp::InterestingInt(v) => {
                let len = self.field_len.min(8);
                let bytes = v.to_be_bytes();
                overwrite_range(data, self.byte_offset, &bytes[8 - len..])
            }
            MutationOp::RandomFill(seed) => {
                let mut out = data.to_vec();
                let mut s = *seed;
                for i in self.byte_offset..(self.byte_offset + self.field_len).min(data.len()) {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    out[i] = (s & 0xFF) as u8;
                }
                out
            }
            MutationOp::Truncate(new_len) => {
                let end = (self.byte_offset + new_len).min(data.len());
                // Keep prefix and suffix, shrink field.
                let mut out = data[..self.byte_offset.min(data.len())].to_vec();
                out.extend_from_slice(&data[self.byte_offset..end]);
                let orig_end = (self.byte_offset + self.field_len).min(data.len());
                if orig_end < data.len() {
                    out.extend_from_slice(&data[orig_end..]);
                }
                out
            }
            MutationOp::Repeat(n) => {
                let end = (self.byte_offset + self.field_len).min(data.len());
                let chunk = data[self.byte_offset..end].to_vec();
                let insert_at = end;
                let repeated: Vec<u8> = chunk.iter().cycle().take(chunk.len() * n).cloned().collect();
                insert_bytes(data, insert_at, &repeated)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ChecksumCorrupt — corrupt specific checksum fields
// ---------------------------------------------------------------------------

/// Checksum algorithm to corrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumKind {
    /// 16-bit one's-complement IP/TCP/UDP checksum.
    Ip16,
    /// CRC-32.
    Crc32,
    /// Simple 8-bit additive checksum.
    Additive8,
    /// Custom offset/length with arbitrary corrupt byte.
    Custom { offset: usize, len: usize },
}

/// Corrupt a checksum field so validation fails.
#[derive(Debug, Clone)]
pub struct ChecksumCorrupt {
    pub kind: ChecksumKind,
    pub checksum_offset: usize,
}

impl ChecksumCorrupt {
    pub fn new(kind: ChecksumKind, offset: usize) -> Self {
        Self { kind, checksum_offset: offset }
    }

    /// Return the corrupted packet (flips the checksum).
    #[must_use]
    pub fn corrupt(&self, data: &[u8]) -> Vec<u8> {
        match self.kind {
            ChecksumKind::Ip16 => {
                let mut out = data.to_vec();
                if self.checksum_offset + 1 < out.len() {
                    let v = u16::from_be_bytes([out[self.checksum_offset], out[self.checksum_offset + 1]]);
                    let bad = v.wrapping_add(1);
                    let b = bad.to_be_bytes();
                    out[self.checksum_offset] = b[0];
                    out[self.checksum_offset + 1] = b[1];
                }
                out
            }
            ChecksumKind::Crc32 => {
                let mut out = data.to_vec();
                if self.checksum_offset + 3 < out.len() {
                    out[self.checksum_offset] ^= 0xFF;
                }
                out
            }
            ChecksumKind::Additive8 => {
                let mut out = data.to_vec();
                if self.checksum_offset < out.len() {
                    out[self.checksum_offset] ^= 0x01;
                }
                out
            }
            ChecksumKind::Custom { offset, len: _ } => {
                let mut out = data.to_vec();
                if offset < out.len() {
                    out[offset] ^= 0xAA;
                }
                out
            }
        }
    }

    /// Recalculate and embed the correct checksum (for crafting valid baseline).
    #[must_use]
    pub fn fix(&self, data: &[u8]) -> Vec<u8> {
        match self.kind {
            ChecksumKind::Ip16 => {
                let mut out = data.to_vec();
                if self.checksum_offset + 1 < out.len() {
                    // Zero out checksum field then compute.
                    out[self.checksum_offset] = 0;
                    out[self.checksum_offset + 1] = 0;
                    let cs = ip16_checksum(&out);
                    let b = cs.to_be_bytes();
                    out[self.checksum_offset] = b[0];
                    out[self.checksum_offset + 1] = b[1];
                }
                out
            }
            ChecksumKind::Crc32 => {
                let mut out = data.to_vec();
                if self.checksum_offset + 3 < out.len() {
                    out[self.checksum_offset] = 0;
                    out[self.checksum_offset + 1] = 0;
                    out[self.checksum_offset + 2] = 0;
                    out[self.checksum_offset + 3] = 0;
                    let cs = simple_crc32(&out);
                    let b = cs.to_be_bytes();
                    out[self.checksum_offset..self.checksum_offset + 4].copy_from_slice(&b);
                }
                out
            }
            _ => data.to_vec(),
        }
    }
}

fn ip16_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn simple_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// LengthCorrupt — corrupt length fields
// ---------------------------------------------------------------------------

/// Strategy for corrupting a length field.
#[derive(Debug, Clone, Copy)]
pub enum LengthStrategy {
    /// Set length to zero.
    Zero,
    /// Set length to u16::MAX (for 2-byte fields).
    MaxU16,
    /// Subtract delta from actual length.
    Undercount(i64),
    /// Add delta to actual length.
    Overcount(i64),
    /// Set to a specific raw value.
    Raw(u64),
}

/// Corrupt a length field in a packet.
#[derive(Debug, Clone)]
pub struct LengthCorrupt {
    pub offset: usize,
    pub field_bytes: usize,
    pub strategy: LengthStrategy,
}

impl LengthCorrupt {
    pub fn new(offset: usize, field_bytes: usize, strategy: LengthStrategy) -> Self {
        Self { offset, field_bytes, strategy }
    }

    #[must_use]
    pub fn corrupt(&self, data: &[u8]) -> Vec<u8> {
        let current = read_uint(data, self.offset, self.field_bytes);
        let new_val = match self.strategy {
            LengthStrategy::Zero => 0,
            LengthStrategy::MaxU16 => 0xFFFF,
            LengthStrategy::Undercount(d) => current.saturating_add_signed(-d),
            LengthStrategy::Overcount(d) => current.saturating_add_signed(d),
            LengthStrategy::Raw(v) => v,
        };
        write_uint(data, self.offset, self.field_bytes, new_val)
    }
}

fn read_uint(data: &[u8], offset: usize, bytes: usize) -> u64 {
    let mut v: u64 = 0;
    for i in 0..bytes {
        if offset + i < data.len() {
            v = (v << 8) | data[offset + i] as u64;
        }
    }
    v
}

fn write_uint(data: &[u8], offset: usize, bytes: usize, value: u64) -> Vec<u8> {
    let mut out = data.to_vec();
    for i in 0..bytes {
        let byte_pos = offset + (bytes - 1 - i);
        if byte_pos < out.len() {
            out[byte_pos] = ((value >> (i * 8)) & 0xFF) as u8;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Protocol-specific mutations
// ---------------------------------------------------------------------------

/// HTTP header injection mutation.
#[must_use]
pub fn http_inject_header(request: &[u8], header: &str) -> Vec<u8> {
    // Find end of first header line (\r\n) and inject after it.
    if let Some(pos) = find_subsequence(request, b"\r\n") {
        let inject = format!("\r\n{}", header).into_bytes();
        insert_bytes(request, pos, &inject)
    } else {
        request.to_vec()
    }
}

/// DNS label overflow: extend the first label to overflow a buffer.
#[must_use]
pub fn dns_label_overflow(query: &[u8], extra_len: usize) -> Vec<u8> {
    // DNS query: 12-byte header then QNAME.
    // First byte of QNAME is label length.
    if query.len() < 13 {
        return query.to_vec();
    }
    let label_offset = 12;
    let label_len = query[label_offset] as usize;
    let overflow: Vec<u8> = std::iter::repeat(b'A').take(extra_len).collect();
    let mut out = query.to_vec();
    // Overwrite label length with overflowed value (truncated to u8).
    let new_len = (label_len + extra_len) & 0xFF;
    out[label_offset] = new_len as u8;
    insert_bytes(&out, label_offset + 1 + label_len, &overflow)
}

/// TLS version confusion: replace `version` bytes with target_version.
#[must_use]
pub fn tls_version_confusion(record: &[u8], target_version: u16) -> Vec<u8> {
    // TLS record: [content_type(1), version(2), length(2), ...]
    if record.len() < 3 {
        return record.to_vec();
    }
    let mut out = record.to_vec();
    let b = target_version.to_be_bytes();
    out[1] = b[0];
    out[2] = b[1];
    out
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// PacketMutator — registry + dispatch
// ---------------------------------------------------------------------------

/// Named mutation step stored in a `PacketMutator`.
#[derive(Debug, Clone)]
pub enum MutatorStep {
    FieldMut(FieldMutation),
    ChecksumCorrupt(ChecksumCorrupt),
    LengthCorrupt(LengthCorrupt),
    BitFlip { bit: usize },
    ByteSubstitute { offset: usize, value: u8 },
    HttpHeaderInject(String),
    DnsLabelOverflow(usize),
    TlsVersionConfusion(u16),
    InsertBytes { offset: usize, bytes: Vec<u8> },
    DeleteBytes { offset: usize, count: usize },
}

impl MutatorStep {
    #[must_use]
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        match self {
            MutatorStep::FieldMut(fm) => fm.apply(data),
            MutatorStep::ChecksumCorrupt(cc) => cc.corrupt(data),
            MutatorStep::LengthCorrupt(lc) => lc.corrupt(data),
            MutatorStep::BitFlip { bit } => flip_bit(data, *bit),
            MutatorStep::ByteSubstitute { offset, value } => substitute_byte(data, *offset, *value),
            MutatorStep::HttpHeaderInject(h) => http_inject_header(data, h),
            MutatorStep::DnsLabelOverflow(n) => dns_label_overflow(data, *n),
            MutatorStep::TlsVersionConfusion(v) => tls_version_confusion(data, *v),
            MutatorStep::InsertBytes { offset, bytes } => insert_bytes(data, *offset, bytes),
            MutatorStep::DeleteBytes { offset, count } => delete_bytes(data, *offset, *count),
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            MutatorStep::FieldMut(_) => "field_mut",
            MutatorStep::ChecksumCorrupt(_) => "checksum_corrupt",
            MutatorStep::LengthCorrupt(_) => "length_corrupt",
            MutatorStep::BitFlip { .. } => "bit_flip",
            MutatorStep::ByteSubstitute { .. } => "byte_substitute",
            MutatorStep::HttpHeaderInject(_) => "http_header_inject",
            MutatorStep::DnsLabelOverflow(_) => "dns_label_overflow",
            MutatorStep::TlsVersionConfusion(_) => "tls_version_confusion",
            MutatorStep::InsertBytes { .. } => "insert_bytes",
            MutatorStep::DeleteBytes { .. } => "delete_bytes",
        }
    }
}

/// A single packet mutator that applies a sequence of steps.
#[derive(Debug, Clone, Default)]
pub struct PacketMutator {
    steps: Vec<MutatorStep>,
    label: String,
}

impl PacketMutator {
    pub fn new(label: impl Into<String>) -> Self {
        Self { label: label.into(), steps: Vec::new() }
    }

    pub fn add_step(&mut self, step: MutatorStep) -> &mut Self {
        self.steps.push(step);
        self
    }

    pub fn with_step(mut self, step: MutatorStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Apply all steps sequentially.
    #[must_use]
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        let mut cur = data.to_vec();
        for step in &self.steps {
            cur = step.apply(&cur);
        }
        cur
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Generate all single-bit-flip variants of a packet.
    #[must_use]
    pub fn all_bit_flips(data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        (0..data.len() * 8)
            .map(|bit| (bit, flip_bit(data, bit)))
            .collect()
    }

    /// Generate variants with interesting integer values for each 1/2/4-byte offset.
    #[must_use]
    pub fn interesting_int_variants(data: &[u8]) -> Vec<Vec<u8>> {
        const INTERESTING: &[u64] = &[
            0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
            0x1_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
        ];
        let mut out = Vec::new();
        for offset in 0..data.len() {
            for &v in INTERESTING {
                for &sz in &[1usize, 2, 4] {
                    if offset + sz <= data.len() {
                        let m = FieldMutation::new("auto", offset, sz, MutationOp::InterestingInt(v));
                        out.push(m.apply(data));
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// MutatorChain — named set of mutators with weighted selection
// ---------------------------------------------------------------------------

/// A chain of named `PacketMutator`s with weights for random selection.
#[derive(Debug, Default)]
pub struct MutatorChain {
    mutators: Vec<(PacketMutator, u32)>,
    total_weight: u32,
    apply_count: u64,
}

impl MutatorChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, mutator: PacketMutator, weight: u32) {
        self.total_weight += weight;
        self.mutators.push((mutator, weight));
    }

    /// Select a mutator by weighted random using a simple xorshift seed.
    #[must_use]
    pub fn select(&self, seed: u64) -> Option<&PacketMutator> {
        if self.total_weight == 0 {
            return None;
        }
        let mut s = seed ^ 0xDEAD_BEEF_CAFE_BABE;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let pick = (s % self.total_weight as u64) as u32;
        let mut acc = 0u32;
        for (m, w) in &self.mutators {
            acc += w;
            if pick < acc {
                return Some(m);
            }
        }
        self.mutators.last().map(|(m, _)| m)
    }

    /// Apply a weighted-randomly-selected mutator.
    #[must_use]
    pub fn apply_random(&mut self, data: &[u8], seed: u64) -> Option<(&str, Vec<u8>)> {
        let label;
        let result;
        if let Some(m) = self.select(seed) {
            label = m.label().to_owned();
            result = m.apply(data);
        } else {
            return None;
        }
        self.apply_count += 1;
        // Find label index — re-borrow
        for (m, _) in &self.mutators {
            if m.label() == label {
                return Some((m.label(), result));
            }
        }
        None
    }

    #[must_use]
    pub fn mutator_count(&self) -> usize {
        self.mutators.len()
    }

    #[must_use]
    pub fn apply_count(&self) -> u64 {
        self.apply_count
    }

    /// Iterate all mutators and apply each to `data`.
    pub fn apply_all<'a>(&'a self, data: &[u8]) -> Vec<(&'a str, Vec<u8>)> {
        self.mutators
            .iter()
            .map(|(m, _)| (m.label(), m.apply(data)))
            .collect()
    }

    /// Build a standard HTTP fuzzing chain.
    #[must_use]
    pub fn http_chain() -> Self {
        let mut chain = Self::new();
        chain.add(
            PacketMutator::new("http_header_inject_crlf")
                .with_step(MutatorStep::HttpHeaderInject("X-Fuzz: \r\nX-Injected: yes".into())),
            10,
        );
        chain.add(
            PacketMutator::new("http_length_zero")
                .with_step(MutatorStep::LengthCorrupt(LengthCorrupt::new(0, 2, LengthStrategy::Zero))),
            5,
        );
        chain.add(
            PacketMutator::new("http_bit_flip_0")
                .with_step(MutatorStep::BitFlip { bit: 0 }),
            3,
        );
        chain
    }

    /// Build a standard DNS fuzzing chain.
    #[must_use]
    pub fn dns_chain() -> Self {
        let mut chain = Self::new();
        chain.add(
            PacketMutator::new("dns_label_overflow_64")
                .with_step(MutatorStep::DnsLabelOverflow(64)),
            10,
        );
        chain.add(
            PacketMutator::new("dns_qdcount_overflow")
                .with_step(MutatorStep::FieldMut(FieldMutation::new(
                    "qdcount", 4, 2, MutationOp::InterestingInt(0xFFFF),
                ))),
            8,
        );
        chain.add(
            PacketMutator::new("dns_txid_zero")
                .with_step(MutatorStep::FieldMut(FieldMutation::new(
                    "txid", 0, 2, MutationOp::InterestingInt(0),
                ))),
            3,
        );
        chain
    }

    /// Build a standard TLS fuzzing chain.
    #[must_use]
    pub fn tls_chain() -> Self {
        let mut chain = Self::new();
        for ver in [0x0200u16, 0x0300, 0x0301, 0x0302, 0x0304, 0xFFFF] {
            chain.add(
                PacketMutator::new(format!("tls_ver_{:04x}", ver))
                    .with_step(MutatorStep::TlsVersionConfusion(ver)),
                5,
            );
        }
        chain.add(
            PacketMutator::new("tls_length_max")
                .with_step(MutatorStep::LengthCorrupt(LengthCorrupt::new(3, 2, LengthStrategy::MaxU16))),
            8,
        );
        chain
    }
}

// ---------------------------------------------------------------------------
// MutationStats — counters for a fuzzing session
// ---------------------------------------------------------------------------

/// Aggregate statistics for mutations applied during a session.
#[derive(Debug, Default, Clone)]
pub struct MutationStats {
    pub total_mutations: u64,
    pub per_type: HashMap<String, u64>,
    pub bytes_produced: u64,
}

impl MutationStats {
    pub fn record(&mut self, step_name: &str, output_len: usize) {
        self.total_mutations += 1;
        *self.per_type.entry(step_name.to_owned()).or_default() += 1;
        self.bytes_produced += output_len as u64;
    }

    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&str, u64)> {
        let mut pairs: Vec<(&str, u64)> = self.per_type.iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flip_bit() {
        let data = vec![0b0000_0000u8];
        let out = flip_bit(&data, 7); // LSB
        assert_eq!(out[0], 0b0000_0001);
        let out2 = flip_bit(&data, 0); // MSB
        assert_eq!(out2[0], 0b1000_0000);
    }

    #[test]
    fn test_substitute_byte() {
        let data = vec![0u8, 1, 2, 3];
        let out = substitute_byte(&data, 2, 0xFF);
        assert_eq!(out, vec![0, 1, 0xFF, 3]);
    }

    #[test]
    fn test_insert_delete() {
        let data = vec![0u8, 1, 2, 3];
        let ins = insert_bytes(&data, 2, &[0xAA, 0xBB]);
        assert_eq!(ins, vec![0, 1, 0xAA, 0xBB, 2, 3]);
        let del = delete_bytes(&ins, 2, 2);
        assert_eq!(del, data);
    }

    #[test]
    fn test_field_mutation_xor() {
        let data = vec![0xFFu8; 4];
        let m = FieldMutation::new("f", 1, 2, MutationOp::XorMask(0x0F));
        let out = m.apply(&data);
        assert_eq!(out, vec![0xFF, 0xF0, 0xF0, 0xFF]);
    }

    #[test]
    fn test_field_mutation_replace() {
        let data = vec![0u8; 6];
        let m = FieldMutation::new("f", 2, 3, MutationOp::Replace(vec![1, 2, 3]));
        let out = m.apply(&data);
        assert_eq!(out, vec![0, 0, 1, 2, 3, 0]);
    }

    #[test]
    fn test_field_mutation_overflow() {
        let data = vec![0u8; 4];
        let m = FieldMutation::new("f", 0, 2, MutationOp::Overflow(vec![0xAA; 4]));
        let out = m.apply(&data);
        // overflow inserts 4 bytes after field end (offset 2)
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn test_checksum_corrupt_ip16() {
        let data = vec![0u8; 20];
        let cc = ChecksumCorrupt::new(ChecksumKind::Ip16, 10);
        let corrupted = cc.corrupt(&data);
        // The original checksum at [10..12] was 0; wrapping_add(1) = 1
        let v = u16::from_be_bytes([corrupted[10], corrupted[11]]);
        assert_eq!(v, 1);
    }

    #[test]
    fn test_length_corrupt_zero() {
        let mut data = vec![0u8; 10];
        data[4] = 0x00;
        data[5] = 0x08;
        let lc = LengthCorrupt::new(4, 2, LengthStrategy::Zero);
        let out = lc.corrupt(&data);
        assert_eq!(out[4], 0);
        assert_eq!(out[5], 0);
    }

    #[test]
    fn test_length_corrupt_overcount() {
        let mut data = vec![0u8; 6];
        data[0] = 0x00;
        data[1] = 0x04; // length = 4
        let lc = LengthCorrupt::new(0, 2, LengthStrategy::Overcount(100));
        let out = lc.corrupt(&data);
        let v = u16::from_be_bytes([out[0], out[1]]);
        assert_eq!(v, 104);
    }

    #[test]
    fn test_http_header_inject() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = http_inject_header(req, "X-Injected: yes");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("X-Injected: yes"));
    }

    #[test]
    fn test_dns_label_overflow() {
        let mut dns = vec![0u8; 12];
        dns.push(3); // label len = 3
        dns.extend_from_slice(b"www");
        dns.push(0); // end of QNAME
        let out = dns_label_overflow(&dns, 32);
        assert!(out.len() > dns.len());
    }

    #[test]
    fn test_tls_version_confusion() {
        let record = vec![0x16u8, 0x03, 0x03, 0x00, 0x10]; // TLS 1.2
        let out = tls_version_confusion(&record, 0x0300); // downgrade to SSL 3.0
        assert_eq!(out[1], 0x03);
        assert_eq!(out[2], 0x00);
    }

    #[test]
    fn test_packet_mutator_chain_apply() {
        let data = vec![0u8; 20];
        let m = PacketMutator::new("test")
            .with_step(MutatorStep::BitFlip { bit: 0 })
            .with_step(MutatorStep::ByteSubstitute { offset: 1, value: 0xFF });
        let out = m.apply(&data);
        assert_eq!(out[0], 0x80);
        assert_eq!(out[1], 0xFF);
    }

    #[test]
    fn test_mutator_chain_select() {
        let chain = MutatorChain::http_chain();
        assert!(chain.mutator_count() >= 2);
        let m = chain.select(42);
        assert!(m.is_some());
    }

    #[test]
    fn test_all_bit_flips_count() {
        let data = vec![0u8; 2];
        let flips = PacketMutator::all_bit_flips(&data);
        assert_eq!(flips.len(), 16);
    }

    #[test]
    fn test_mutation_stats() {
        let mut stats = MutationStats::default();
        stats.record("bit_flip", 20);
        stats.record("bit_flip", 20);
        stats.record("length_corrupt", 20);
        assert_eq!(stats.total_mutations, 3);
        let top = stats.top_n(1);
        assert_eq!(top[0].0, "bit_flip");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_interesting_int_variants_nonempty() {
        let data = vec![0u8; 8];
        let vars = PacketMutator::interesting_int_variants(&data);
        assert!(!vars.is_empty());
    }
}
