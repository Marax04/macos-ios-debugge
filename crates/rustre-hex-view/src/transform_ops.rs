//! Binary transform operations for hex view regions.
//!
//! Key types:
//! - [`TransformOp`] trait — in-place transform of a byte region.
//! - [`XorTransform`] — XOR all bytes with a fixed key.
//! - [`AddTransform`] — add a constant to all bytes.
//! - [`RotTransform`] — bit-rotate all bytes left/right.
//! - [`ReverseTransform`] — reverse byte order.
//! - [`Base64Transform`] — base64 encode/decode a region.
//! - [`CompressionTransform`] — gzip/deflate expand stub.
//! - [`TransformHistory`] — stack of applied transforms with undo.

use std::fmt;

// ---------------------------------------------------------------------------
// TransformOp trait
// ---------------------------------------------------------------------------

/// A transformation that can be applied to a mutable byte slice.
pub trait TransformOp: fmt::Debug + Send + Sync {
    /// Human-readable name.
    fn name(&self) -> &str;

    /// Apply the transform to `data` in-place.
    fn apply(&self, data: &mut Vec<u8>);

    /// Apply the inverse transform to `data` in-place.
    ///
    /// For non-invertible transforms this is a no-op.
    fn apply_inverse(&self, data: &mut Vec<u8>) {
        self.apply(data); // default: self-inverse (e.g. XOR with same key)
    }

    /// Returns `true` if the transform is reversible (has a proper inverse).
    fn is_reversible(&self) -> bool {
        true
    }

    /// Short description of the transform.
    fn description(&self) -> String {
        self.name().to_string()
    }
}

// ---------------------------------------------------------------------------
// XorTransform
// ---------------------------------------------------------------------------

/// XOR every byte with a repeating key.
#[derive(Debug, Clone)]
pub struct XorTransform {
    /// XOR key bytes.  Repeats if shorter than the data.
    pub key: Vec<u8>,
}

impl XorTransform {
    /// Create with a single-byte key.
    #[must_use]
    pub fn single(key: u8) -> Self {
        Self { key: vec![key] }
    }

    /// Create with a multi-byte key.
    #[must_use]
    pub const fn multi(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl TransformOp for XorTransform {
    fn name(&self) -> &'static str {
        "XOR"
    }

    fn apply(&self, data: &mut Vec<u8>) {
        if self.key.is_empty() {
            return;
        }
        let klen = self.key.len();
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.key[i % klen];
        }
    }

    // XOR is self-inverse.
    fn apply_inverse(&self, data: &mut Vec<u8>) {
        self.apply(data);
    }

    fn description(&self) -> String {
        if self.key.len() == 1 {
            format!("XOR with {:#x}", self.key[0])
        } else {
            format!("XOR with {}-byte key", self.key.len())
        }
    }
}

// ---------------------------------------------------------------------------
// AddTransform
// ---------------------------------------------------------------------------

/// Add a constant modulo 256 to every byte.
#[derive(Debug, Clone)]
pub struct AddTransform {
    pub addend: u8,
}

impl AddTransform {
    #[must_use]
    pub const fn new(addend: u8) -> Self {
        Self { addend }
    }
}

impl TransformOp for AddTransform {
    fn name(&self) -> &'static str {
        "ADD"
    }

    fn apply(&self, data: &mut Vec<u8>) {
        for b in data.iter_mut() {
            *b = b.wrapping_add(self.addend);
        }
    }

    fn apply_inverse(&self, data: &mut Vec<u8>) {
        for b in data.iter_mut() {
            *b = b.wrapping_sub(self.addend);
        }
    }

    fn description(&self) -> String {
        format!("ADD {:#x} to every byte", self.addend)
    }
}

// ---------------------------------------------------------------------------
// RotTransform
// ---------------------------------------------------------------------------

/// Rotate every byte left (positive) or right (negative) by `amount` bits.
#[derive(Debug, Clone)]
pub struct RotTransform {
    /// Rotation amount in bits.  Positive = left, negative = right.
    pub amount: i8,
}

impl RotTransform {
    #[must_use]
    pub const fn left(bits: u8) -> Self {
        Self { amount: bits as i8 }
    }

    #[must_use]
    pub const fn right(bits: u8) -> Self {
        Self {
            amount: -(bits as i8),
        }
    }
}

impl TransformOp for RotTransform {
    fn name(&self) -> &'static str {
        "ROT"
    }

    fn apply(&self, data: &mut Vec<u8>) {
        let amount = self.amount.rem_euclid(8) as u32;
        for b in data.iter_mut() {
            *b = b.rotate_left(amount);
        }
    }

    fn apply_inverse(&self, data: &mut Vec<u8>) {
        let amount = self.amount.rem_euclid(8) as u32;
        for b in data.iter_mut() {
            *b = b.rotate_right(amount);
        }
    }

    fn description(&self) -> String {
        if self.amount >= 0 {
            format!("Rotate left {} bit(s)", self.amount)
        } else {
            format!("Rotate right {} bit(s)", -self.amount)
        }
    }
}

// ---------------------------------------------------------------------------
// ReverseTransform
// ---------------------------------------------------------------------------

/// Reverse the byte order of the region.
#[derive(Debug, Clone, Default)]
pub struct ReverseTransform;

impl TransformOp for ReverseTransform {
    fn name(&self) -> &'static str {
        "REVERSE"
    }
    fn apply(&self, data: &mut Vec<u8>) {
        data.reverse();
    }
    fn apply_inverse(&self, data: &mut Vec<u8>) {
        data.reverse();
    }
    fn description(&self) -> String {
        "Reverse byte order".to_string()
    }
}

// ---------------------------------------------------------------------------
// Base64Transform
// ---------------------------------------------------------------------------

/// Base64 encode or decode a region.
#[derive(Debug, Clone)]
pub struct Base64Transform {
    /// `true` = encode, `false` = decode.
    pub encode: bool,
}

impl Base64Transform {
    #[must_use]
    pub const fn encoder() -> Self {
        Self { encode: true }
    }
    #[must_use]
    pub const fn decoder() -> Self {
        Self { encode: false }
    }
}

/// Minimal base64 encode without external dependencies.
fn b64_encode(data: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize]);
        out.push(ALPHABET[((b0 & 3) << 4 | b1 >> 4) as usize]);
        if chunk.len() >= 2 {
            out.push(ALPHABET[((b1 & 0xF) << 2 | b2 >> 6) as usize]);
        } else {
            out.push(b'=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHABET[(b2 & 63) as usize]);
        } else {
            out.push(b'=');
        }
    }
    out
}

fn b64_decode(data: &[u8]) -> Vec<u8> {
    let decode_char = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0xFF,
        }
    };
    let cleaned: Vec<u8> = data
        .iter()
        .copied()
        .filter(|&c| c != b'=' && decode_char(c) != 0xFF)
        .collect();
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4 + 3);
    for chunk in cleaned.chunks(4) {
        let v: Vec<u8> = chunk.iter().map(|&c| decode_char(c)).collect();
        if v.len() >= 2 {
            out.push((v[0] << 2) | (v[1] >> 4));
        }
        if v.len() >= 3 {
            out.push((v[1] << 4) | (v[2] >> 2));
        }
        if v.len() >= 4 {
            out.push((v[2] << 6) | v[3]);
        }
    }
    out
}

impl TransformOp for Base64Transform {
    fn name(&self) -> &str {
        if self.encode {
            "BASE64_ENC"
        } else {
            "BASE64_DEC"
        }
    }

    fn apply(&self, data: &mut Vec<u8>) {
        let result = if self.encode {
            b64_encode(data)
        } else {
            b64_decode(data)
        };
        *data = result;
    }

    fn apply_inverse(&self, data: &mut Vec<u8>) {
        // Inverse of encode is decode and vice versa.
        let result = if self.encode {
            b64_decode(data)
        } else {
            b64_encode(data)
        };
        *data = result;
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn description(&self) -> String {
        if self.encode {
            "Base64 encode region".to_string()
        } else {
            "Base64 decode region".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// CompressionTransform
// ---------------------------------------------------------------------------

/// A stub compression/decompression transform.
///
/// This does not perform actual gzip decompression (that would require `flate2`);
/// instead it checks for gzip magic and strips the header as a stub demonstration.
#[derive(Debug, Clone, Default)]
pub struct CompressionTransform;

impl TransformOp for CompressionTransform {
    fn name(&self) -> &'static str {
        "DECOMPRESS"
    }

    fn apply(&self, data: &mut Vec<u8>) {
        // Stub: if data starts with gzip magic (1F 8B), strip the 10-byte header.
        if data.len() > 10 && data[0] == 0x1F && data[1] == 0x8B {
            *data = data[10..].to_vec();
        }
        // Otherwise no-op.
    }

    fn is_reversible(&self) -> bool {
        false
    }
    fn description(&self) -> String {
        "Attempt gzip expand (strip 10-byte header)".to_string()
    }
}

// ---------------------------------------------------------------------------
// TransformRecord
// ---------------------------------------------------------------------------

/// A record of a transform that was applied.
#[derive(Debug)]
pub struct TransformRecord {
    /// The transform that was applied.
    pub transform: Box<dyn TransformOp>,
    /// Snapshot of data *before* the transform (for undo).
    pub before_snapshot: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// TransformHistory
// ---------------------------------------------------------------------------

/// Stack of applied transforms with undo support.
pub struct TransformHistory {
    /// Stack of applied transforms.
    stack: Vec<TransformRecord>,
    /// Maximum number of undo levels.
    pub max_undo: usize,
}

impl TransformHistory {
    #[must_use]
    pub const fn new(max_undo: usize) -> Self {
        Self {
            stack: Vec::new(),
            max_undo,
        }
    }

    /// Apply `transform` to `data`, recording the operation.
    pub fn apply(&mut self, transform: Box<dyn TransformOp>, data: &mut Vec<u8>) {
        let snapshot = if transform.is_reversible() {
            Some(data.clone())
        } else {
            None
        };
        transform.apply(data);
        // Trim history if too long.
        while self.stack.len() >= self.max_undo {
            self.stack.remove(0);
        }
        self.stack.push(TransformRecord {
            transform,
            before_snapshot: snapshot,
        });
    }

    /// Undo the last applied transform.
    ///
    /// Returns `true` on success, `false` if nothing to undo.
    pub fn undo(&mut self, data: &mut Vec<u8>) -> bool {
        if let Some(record) = self.stack.pop() {
            if let Some(snapshot) = record.before_snapshot {
                *data = snapshot;
                return true;
            }
            // Non-reversible: try applying inverse.
            record.transform.apply_inverse(data);
            return true;
        }
        false
    }

    /// Number of operations that can be undone.
    #[must_use]
    pub const fn undo_depth(&self) -> usize {
        self.stack.len()
    }

    /// Names of applied transforms in order.
    #[must_use]
    pub fn history(&self) -> Vec<String> {
        self.stack
            .iter()
            .map(|r| r.transform.description())
            .collect()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.stack.clear();
    }

    /// Returns `true` if there is anything to undo.
    #[must_use]
    pub const fn can_undo(&self) -> bool {
        !self.stack.is_empty()
    }
}

impl fmt::Debug for TransformHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransformHistory {{ depth: {} }}", self.undo_depth())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_single_byte() {
        let t = XorTransform::single(0xFF);
        let mut data = vec![0x00u8, 0xAA, 0xFF];
        t.apply(&mut data);
        assert_eq!(data, [0xFF, 0x55, 0x00]);
    }

    #[test]
    fn test_xor_self_inverse() {
        let t = XorTransform::single(0x42);
        let original = vec![0x01u8, 0x02, 0x03];
        let mut data = original.clone();
        t.apply(&mut data);
        t.apply_inverse(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_multi_key() {
        let t = XorTransform::multi(vec![0xAA, 0xBB]);
        let mut data = vec![0xAA, 0xBB, 0xAA, 0xBB];
        t.apply(&mut data);
        assert_eq!(data, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_xor_empty_key_noop() {
        let t = XorTransform { key: vec![] };
        let mut data = vec![0x01u8, 0x02];
        t.apply(&mut data);
        assert_eq!(data, [0x01, 0x02]);
    }

    #[test]
    fn test_add_transform() {
        let t = AddTransform::new(1);
        let mut data = vec![0xFEu8, 0xFF, 0x00];
        t.apply(&mut data);
        assert_eq!(data, [0xFF, 0x00, 0x01]);
    }

    #[test]
    fn test_add_inverse() {
        let t = AddTransform::new(5);
        let original = vec![10u8, 20, 30];
        let mut data = original.clone();
        t.apply(&mut data);
        t.apply_inverse(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_rot_left_1() {
        let t = RotTransform::left(1);
        let mut data = vec![0b1000_0001u8];
        t.apply(&mut data);
        assert_eq!(data[0], 0b0000_0011);
    }

    #[test]
    fn test_rot_inverse() {
        let t = RotTransform::left(3);
        let original = vec![0xABu8, 0xCDu8];
        let mut data = original.clone();
        t.apply(&mut data);
        t.apply_inverse(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_reverse_transform() {
        let t = ReverseTransform;
        let mut data = vec![1u8, 2, 3];
        t.apply(&mut data);
        assert_eq!(data, [3, 2, 1]);
    }

    #[test]
    fn test_reverse_self_inverse() {
        let t = ReverseTransform;
        let original = vec![0xAAu8, 0xBBu8, 0xCCu8];
        let mut data = original.clone();
        t.apply(&mut data);
        t.apply_inverse(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_base64_encode_decode_round_trip() {
        let t = Base64Transform::encoder();
        let original = b"Hello, world!".to_vec();
        let mut data = original.clone();
        t.apply(&mut data);
        let encoded = data.clone();
        assert_ne!(encoded, original);
        let dt = Base64Transform::decoder();
        dt.apply(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_base64_encode_known() {
        let encoded = b64_encode(b"Man");
        assert_eq!(encoded, b"TWFu");
    }

    #[test]
    fn test_base64_decode_known() {
        let decoded = b64_decode(b"TWFu");
        assert_eq!(decoded, b"Man");
    }

    #[test]
    fn test_compression_gzip_strip() {
        let t = CompressionTransform;
        let mut data = vec![0x1Fu8, 0x8B];
        data.extend_from_slice(&[0u8; 10]); // minimal gzip header
        data.extend_from_slice(b"payload");
        let orig_len = data.len();
        t.apply(&mut data);
        assert!(data.len() < orig_len);
    }

    #[test]
    fn test_compression_non_gzip_noop() {
        let t = CompressionTransform;
        let original = vec![0xAAu8, 0xBBu8, 0xCCu8];
        let mut data = original.clone();
        t.apply(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_transform_history_apply_undo() {
        let mut history = TransformHistory::new(10);
        let mut data = vec![0x01u8, 0x02, 0x03];
        let original = data.clone();
        history.apply(Box::new(XorTransform::single(0xFF)), &mut data);
        assert_ne!(data, original);
        history.undo(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_transform_history_multiple_undos() {
        let mut history = TransformHistory::new(10);
        let mut data = vec![0x00u8; 4];
        history.apply(Box::new(AddTransform::new(1)), &mut data);
        history.apply(Box::new(AddTransform::new(1)), &mut data);
        assert_eq!(data, [2, 2, 2, 2]);
        history.undo(&mut data);
        assert_eq!(data, [1, 1, 1, 1]);
        history.undo(&mut data);
        assert_eq!(data, [0, 0, 0, 0]);
    }

    #[test]
    fn test_transform_history_can_undo() {
        let mut history = TransformHistory::new(10);
        let mut data = vec![0u8; 4];
        assert!(!history.can_undo());
        history.apply(Box::new(XorTransform::single(0x00)), &mut data);
        assert!(history.can_undo());
    }

    #[test]
    fn test_transform_history_clear() {
        let mut history = TransformHistory::new(10);
        let mut data = vec![0u8; 4];
        history.apply(Box::new(ReverseTransform), &mut data);
        history.clear();
        assert_eq!(history.undo_depth(), 0);
    }

    #[test]
    fn test_transform_history_max_undo() {
        let mut history = TransformHistory::new(2);
        let mut data = vec![0u8; 4];
        history.apply(Box::new(AddTransform::new(1)), &mut data);
        history.apply(Box::new(AddTransform::new(1)), &mut data);
        history.apply(Box::new(AddTransform::new(1)), &mut data); // pushes oldest out
        assert_eq!(history.undo_depth(), 2);
    }

    #[test]
    fn test_transform_history_names() {
        let mut history = TransformHistory::new(10);
        let mut data = vec![0u8; 4];
        history.apply(Box::new(XorTransform::single(0x01)), &mut data);
        history.apply(Box::new(AddTransform::new(2)), &mut data);
        let h = history.history();
        assert_eq!(h.len(), 2);
    }
}
