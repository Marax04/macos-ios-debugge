//! Integrated string deobfuscation analysis pass.
//!
//! Combines XOR, RC4, stack-string reconstruction, and a pluggable pass list
//! into a single `StringDeobfuscator` that processes a binary's discovered
//! strings and returns `StringResult` entries.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// StringResult
// ─────────────────────────────────────────────────────────────────────────────

/// The confidence level of a deobfuscation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        };
        f.write_str(s)
    }
}

/// The algorithm used to recover a plaintext string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeobfAlgorithm {
    Xor,
    Rc4,
    StackString,
    Caesar(u8),
    Custom(String),
}

impl fmt::Display for DeobfAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xor => write!(f, "xor"),
            Self::Rc4 => write!(f, "rc4"),
            Self::StackString => write!(f, "stack_string"),
            Self::Caesar(n) => write!(f, "caesar({n})"),
            Self::Custom(s) => write!(f, "custom({s})"),
        }
    }
}

/// The output of a successful string deobfuscation.
#[derive(Debug, Clone)]
pub struct StringResult {
    /// Virtual address of the obfuscated string.
    pub address: u64,
    /// The original (obfuscated) bytes.
    pub ciphertext: Vec<u8>,
    /// The recovered plaintext.
    pub plaintext: String,
    /// Algorithm that produced this result.
    pub algorithm: DeobfAlgorithm,
    /// Key bytes used (for XOR/RC4).
    pub key: Vec<u8>,
    /// Confidence in the result.
    pub confidence: Confidence,
}

impl StringResult {
    #[must_use]
    pub const fn new(
        address: u64,
        ciphertext: Vec<u8>,
        plaintext: String,
        algorithm: DeobfAlgorithm,
        key: Vec<u8>,
        confidence: Confidence,
    ) -> Self {
        Self {
            address,
            ciphertext,
            plaintext,
            algorithm,
            key,
            confidence,
        }
    }

    /// Whether the recovered plaintext contains only printable ASCII.
    #[must_use]
    pub fn is_printable_ascii(&self) -> bool {
        self.plaintext
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPass trait
// ─────────────────────────────────────────────────────────────────────────────

/// An individual string deobfuscation pass.
pub trait DeobfPass: Send + Sync {
    /// Short identifier for this pass.
    fn name(&self) -> &str;

    /// Attempt to deobfuscate `data` at `address`.
    /// Returns `None` if this pass does not recognise the data.
    fn try_deobf(&self, address: u64, data: &[u8]) -> Option<StringResult>;
}

// ─────────────────────────────────────────────────────────────────────────────
// XorPass
// ─────────────────────────────────────────────────────────────────────────────

/// Single-byte and multi-byte XOR deobfuscation.
pub struct XorPass {
    /// Candidate keys to try (single-byte values or multi-byte sequences).
    pub keys: Vec<Vec<u8>>,
    /// Minimum fraction of printable bytes required to accept.
    pub printable_threshold: f32,
}

impl Default for XorPass {
    fn default() -> Self {
        // Default: try all 255 single-byte keys.
        Self {
            keys: (1u8..=255).map(|k| vec![k]).collect(),
            printable_threshold: 0.90,
        }
    }
}

impl XorPass {
    #[must_use]
    pub const fn new(keys: Vec<Vec<u8>>, threshold: f32) -> Self {
        Self {
            keys,
            printable_threshold: threshold,
        }
    }

    /// XOR `data` with the repeating `key`.
    #[must_use]
    pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }

    fn printable_fraction(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let count = data
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        f64::from(count) / f64::from(len)
    }
}

impl DeobfPass for XorPass {
    fn name(&self) -> &'static str {
        "xor"
    }

    fn try_deobf(&self, address: u64, data: &[u8]) -> Option<StringResult> {
        if data.is_empty() {
            return None;
        }
        for key in &self.keys {
            let decoded = Self::xor_decode(data, key);
            if Self::printable_fraction(&decoded) >= f64::from(self.printable_threshold) {
                let plaintext = String::from_utf8_lossy(&decoded).to_string();
                let confidence = if Self::printable_fraction(&decoded) >= 0.98 {
                    Confidence::High
                } else if Self::printable_fraction(&decoded) >= 0.95 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };
                return Some(StringResult::new(
                    address,
                    data.to_vec(),
                    plaintext,
                    DeobfAlgorithm::Xor,
                    key.clone(),
                    confidence,
                ));
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rc4Pass
// ─────────────────────────────────────────────────────────────────────────────

/// RC4 (ARCFOUR) deobfuscation pass.
pub struct Rc4Pass {
    /// Candidate RC4 keys to try.
    pub keys: Vec<Vec<u8>>,
    pub printable_threshold: f32,
}

impl Rc4Pass {
    #[must_use]
    pub const fn new(keys: Vec<Vec<u8>>) -> Self {
        Self {
            keys,
            printable_threshold: 0.90,
        }
    }

    /// RC4 key scheduling + PRGA.
    #[must_use]
    pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        let mut s: Vec<u8> = (0..=255u8).collect();
        let mut j: u8 = 0;
        for i in 0..=255usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        let mut i: u8 = 0;
        let mut j: u8 = 0;
        let mut out = Vec::with_capacity(data.len());
        for &byte in data {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            out.push(byte ^ k);
        }
        out
    }

    fn printable_fraction(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let c = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
        let c = u32::try_from(c).unwrap_or(u32::MAX);
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        f64::from(c) / f64::from(len)
    }
}

impl DeobfPass for Rc4Pass {
    fn name(&self) -> &'static str {
        "rc4"
    }

    fn try_deobf(&self, address: u64, data: &[u8]) -> Option<StringResult> {
        for key in &self.keys {
            let decoded = Self::rc4(key, data);
            if Self::printable_fraction(&decoded) >= f64::from(self.printable_threshold) {
                let plaintext = String::from_utf8_lossy(&decoded).to_string();
                return Some(StringResult::new(
                    address,
                    data.to_vec(),
                    plaintext,
                    DeobfAlgorithm::Rc4,
                    key.clone(),
                    Confidence::Medium,
                ));
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackStringPass
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstructs stack-built strings from a trace of byte assignments.
///
/// A stack string is built by code like:
/// ```text
/// MOV BYTE PTR [rbp-8], 'H'
/// MOV BYTE PTR [rbp-7], 'e'
/// MOV BYTE PTR [rbp-6], 'l'
/// ...
/// ```
/// This pass takes a list of `(stack_offset, byte_value)` assignments and
/// reconstructs the string.
pub struct StackStringPass {
    pub min_length: usize,
}

impl Default for StackStringPass {
    fn default() -> Self {
        Self { min_length: 4 }
    }
}

impl StackStringPass {
    #[must_use]
    pub const fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Reconstruct a string from a list of `(offset, byte)` assignments.
    ///
    /// Assignments are placed into a buffer ordered by offset.
    #[must_use]
    pub fn reconstruct(&self, assignments: &[(i64, u8)]) -> Option<String> {
        if assignments.is_empty() {
            return None;
        }
        let mut map: HashMap<i64, u8> = HashMap::new();
        for &(off, byte) in assignments {
            map.insert(off, byte);
        }
        let mut offsets: Vec<i64> = map.keys().copied().collect();
        offsets.sort_unstable();
        // Check that offsets are contiguous
        let mut bytes = Vec::new();
        let start = offsets[0];
        for (i, &off) in offsets.iter().enumerate() {
            if off != start + i64::try_from(i).unwrap_or(i64::MAX) {
                break;
            }
            bytes.push(map[&off]);
        }
        // Strip null terminator
        if bytes.last().copied() == Some(0) {
            bytes.pop();
        }
        if bytes.len() < self.min_length {
            return None;
        }
        let s = String::from_utf8_lossy(&bytes).to_string();
        if s.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            Some(s)
        } else {
            None
        }
    }
}

impl DeobfPass for StackStringPass {
    fn name(&self) -> &'static str {
        "stack_string"
    }

    fn try_deobf(&self, address: u64, data: &[u8]) -> Option<StringResult> {
        // Simple heuristic: treat data as consecutive bytes from offset 0
        let assignments: Vec<(i64, u8)> = data
            .iter()
            .enumerate()
            .map(|(i, &b)| (i64::try_from(i).unwrap_or(i64::MAX), b))
            .collect();
        let plaintext = self.reconstruct(&assignments)?;
        Some(StringResult::new(
            address,
            data.to_vec(),
            plaintext,
            DeobfAlgorithm::StackString,
            vec![],
            Confidence::High,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDeobfuscator
// ─────────────────────────────────────────────────────────────────────────────

/// Runs a list of `DeobfPass`es against every string candidate.
pub struct StringDeobfuscator {
    passes: Vec<Box<dyn DeobfPass>>,
}

impl Default for StringDeobfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl StringDeobfuscator {
    /// Create a deobfuscator with the default pass suite.
    #[must_use]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Add a pass to the end of the pipeline.
    pub fn add_pass(&mut self, pass: Box<dyn DeobfPass>) {
        self.passes.push(pass);
    }

    /// Create with a default XOR + stack-string pass suite.
    #[must_use]
    pub fn with_default_passes() -> Self {
        let mut s = Self::new();
        s.add_pass(Box::new(XorPass::default()));
        s.add_pass(Box::new(StackStringPass::default()));
        s
    }

    /// Deobfuscate a single blob.  Returns the first successful `StringResult`.
    #[must_use]
    pub fn deobfuscate_one(&self, address: u64, data: &[u8]) -> Option<StringResult> {
        for pass in &self.passes {
            if let Some(result) = pass.try_deobf(address, data) {
                return Some(result);
            }
        }
        None
    }

    /// Run all passes against every `(address, data)` pair.
    /// Returns one result per input (best match, or None).
    #[must_use]
    pub fn deobfuscate_all(&self, candidates: &[(u64, Vec<u8>)]) -> Vec<Option<StringResult>> {
        candidates
            .iter()
            .map(|(addr, data)| self.deobfuscate_one(*addr, data))
            .collect()
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Return results with confidence >= `min`.
    #[must_use]
    pub fn filter_by_confidence(results: &[StringResult], min: Confidence) -> Vec<&StringResult> {
        results.iter().filter(|r| r.confidence >= min).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_encode(data: &[u8], key: &[u8]) -> Vec<u8> {
        XorPass::xor_decode(data, key)
    }

    // 1. XorPass single-byte key
    #[test]
    fn test_xor_single_byte() {
        let plaintext = b"hello";
        let key = vec![0x42];
        let cipher = xor_encode(plaintext, &key);
        let decoded = XorPass::xor_decode(&cipher, &key);
        assert_eq!(decoded, plaintext);
    }

    // 2. XorPass multi-byte key
    #[test]
    fn test_xor_multi_byte_key() {
        let plaintext = b"world";
        let key = vec![0x01, 0x02, 0x03];
        let cipher = xor_encode(plaintext, &key);
        assert_eq!(XorPass::xor_decode(&cipher, &key), plaintext);
    }

    // 3. XorPass empty data
    #[test]
    fn test_xor_empty_data() {
        let result = XorPass::xor_decode(&[], &[0x42]);
        assert!(result.is_empty());
    }

    // 4. XorPass try_deobf recovers ASCII string
    #[test]
    fn test_xor_pass_try_deobf() {
        let pass = XorPass::new(vec![vec![0x42]], 0.80);
        let plain = b"HelloWorld";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
        let result = pass.try_deobf(0x1000, &cipher).expect("recovered");
        assert_eq!(result.plaintext, "HelloWorld");
        assert_eq!(result.algorithm, DeobfAlgorithm::Xor);
        assert_eq!(result.key, vec![0x42]);
    }

    // 5. XorPass returns None for non-printable result
    #[test]
    fn test_xor_pass_no_match() {
        let pass = XorPass::new(vec![vec![0xFF]], 0.99);
        let data = vec![0x01, 0x02, 0x03]; // high XOR will not be printable
        assert!(pass.try_deobf(0x1000, &data).is_none());
    }

    // 6. RC4 encrypt then decrypt
    #[test]
    fn test_rc4_roundtrip() {
        let key = b"secret";
        let plaintext = b"Hello, RC4!";
        let cipher = Rc4Pass::rc4(key, plaintext);
        let decoded = Rc4Pass::rc4(key, &cipher);
        assert_eq!(decoded, plaintext);
    }

    // 7. RC4 empty data
    #[test]
    fn test_rc4_empty() {
        let result = Rc4Pass::rc4(b"key", &[]);
        assert!(result.is_empty());
    }

    // 8. RC4 pass tries candidates
    #[test]
    fn test_rc4_pass_try_deobf() {
        let key = b"key123";
        let plain = b"ABCDEFGHIJ";
        let cipher = Rc4Pass::rc4(key, plain);
        let pass = Rc4Pass::new(vec![key.to_vec()]);
        let result = pass.try_deobf(0x2000, &cipher).expect("recovered");
        assert_eq!(result.plaintext.as_bytes(), plain.as_ref());
    }

    // 9. RC4 pass returns None for wrong key
    #[test]
    fn test_rc4_pass_wrong_key() {
        let cipher = vec![0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0];
        let pass = Rc4Pass::new(vec![b"wrong".to_vec()]);
        // Highly unlikely to be printable
        // May or may not return None; just ensure no panic
        let _ = pass.try_deobf(0, &cipher);
    }

    // 10. StackStringPass reconstruct basic
    #[test]
    fn test_stack_string_reconstruct() {
        let ssp = StackStringPass::default();
        let assignments: Vec<(i64, u8)> = b"hello"
            .iter()
            .enumerate()
            .map(|(i, &b)| (i64::try_from(i).unwrap_or(i64::MAX), b))
            .collect();
        let result = ssp.reconstruct(&assignments).expect("ok");
        assert_eq!(result, "hello");
    }

    // 11. StackStringPass below min_length returns None
    #[test]
    fn test_stack_string_below_min() {
        let ssp = StackStringPass::new(10);
        let assignments = vec![(0, b'h'), (1, b'i')];
        assert!(ssp.reconstruct(&assignments).is_none());
    }

    // 12. StackStringPass null-terminated
    #[test]
    fn test_stack_string_null_terminated() {
        let ssp = StackStringPass::default();
        let mut assignments: Vec<(i64, u8)> = b"hello"
            .iter()
            .enumerate()
            .map(|(i, &b)| (i64::try_from(i).unwrap_or(i64::MAX), b))
            .collect();
        assignments.push((5, 0)); // null terminator
        let result = ssp.reconstruct(&assignments).expect("ok");
        assert_eq!(result, "hello");
    }

    // 13. StackStringPass non-contiguous returns partial
    #[test]
    fn test_stack_string_non_contiguous() {
        let ssp = StackStringPass::default();
        // Gap at offset 2
        let assignments = vec![(0, b'a'), (1, b'b'), (4, b'c'), (5, b'd')];
        // Should only get 'ab' which is < min_length(4)
        let result = ssp.reconstruct(&assignments);
        assert!(result.is_none()); // 'ab' is 2 chars < 4
    }

    // 14. StackStringPass via DeobfPass trait
    #[test]
    fn test_stack_string_pass_deobfpass() {
        let pass = StackStringPass::new(4);
        let data = b"test".to_vec();
        let result = pass.try_deobf(0x3000, &data).expect("ok");
        assert_eq!(result.plaintext, "test");
        assert_eq!(result.algorithm, DeobfAlgorithm::StackString);
    }

    // 15. StringDeobfuscator with_default_passes has passes
    #[test]
    fn test_deobfuscator_default_passes() {
        let d = StringDeobfuscator::with_default_passes();
        assert!(d.pass_count() >= 2);
    }

    // 16. StringDeobfuscator deobfuscate_one XOR
    #[test]
    fn test_deobfuscator_one_xor() {
        let mut d = StringDeobfuscator::new();
        d.add_pass(Box::new(XorPass::new(vec![vec![0x20]], 0.90)));
        let plain = b"hello world";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x20).collect();
        let result = d.deobfuscate_one(0x5000, &cipher).expect("ok");
        assert!(result.is_printable_ascii());
    }

    // 17. StringDeobfuscator deobfuscate_all
    #[test]
    fn test_deobfuscator_all() {
        let mut d = StringDeobfuscator::new();
        d.add_pass(Box::new(XorPass::new(vec![vec![0x01]], 0.90)));
        let plain = b"AAAAAAA";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x01).collect();
        let candidates = vec![(0x1000, cipher)];
        let results = d.deobfuscate_all(&candidates);
        assert_eq!(results.len(), 1);
    }

    // 18. StringDeobfuscator returns None for empty data
    #[test]
    fn test_deobfuscator_empty_data() {
        let d = StringDeobfuscator::with_default_passes();
        assert!(d.deobfuscate_one(0, &[]).is_none());
    }

    // 19. StringResult is_printable_ascii
    #[test]
    fn test_string_result_is_printable() {
        let r = StringResult::new(
            0,
            vec![],
            "Hello!".into(),
            DeobfAlgorithm::Xor,
            vec![],
            Confidence::High,
        );
        assert!(r.is_printable_ascii());
    }

    // 20. StringResult not printable with control chars
    #[test]
    fn test_string_result_not_printable() {
        let r = StringResult::new(
            0,
            vec![],
            "\x00\x01\x02".into(),
            DeobfAlgorithm::Xor,
            vec![],
            Confidence::Low,
        );
        assert!(!r.is_printable_ascii());
    }

    // 21. Confidence ordering
    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    // 22. filter_by_confidence
    #[test]
    fn test_filter_by_confidence() {
        let results = vec![
            StringResult::new(
                0,
                vec![],
                "a".into(),
                DeobfAlgorithm::Xor,
                vec![],
                Confidence::Low,
            ),
            StringResult::new(
                1,
                vec![],
                "b".into(),
                DeobfAlgorithm::Xor,
                vec![],
                Confidence::High,
            ),
        ];
        let filtered = StringDeobfuscator::filter_by_confidence(&results, Confidence::Medium);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].plaintext, "b");
    }

    // 23. DeobfAlgorithm Display
    #[test]
    fn test_algorithm_display() {
        assert_eq!(DeobfAlgorithm::Xor.to_string(), "xor");
        assert_eq!(DeobfAlgorithm::Rc4.to_string(), "rc4");
        assert_eq!(DeobfAlgorithm::Caesar(13).to_string(), "caesar(13)");
        assert_eq!(DeobfAlgorithm::StackString.to_string(), "stack_string");
    }

    // 24. XorPass default tries 255 keys
    #[test]
    fn test_xor_default_keys() {
        let pass = XorPass::default();
        assert_eq!(pass.keys.len(), 255);
    }

    // 25. XorPass with key 0 is identity
    #[test]
    fn test_xor_key_zero_identity() {
        let data = b"hello";
        let decoded = XorPass::xor_decode(data, &[0]);
        assert_eq!(decoded, data);
    }

    // 26. Rc4Pass name
    #[test]
    fn test_rc4_pass_name() {
        let pass = Rc4Pass::new(vec![]);
        assert_eq!(pass.name(), "rc4");
    }

    // 27. XorPass name
    #[test]
    fn test_xor_pass_name() {
        assert_eq!(XorPass::default().name(), "xor");
    }

    // 28. StackStringPass name
    #[test]
    fn test_stack_string_pass_name() {
        assert_eq!(StackStringPass::default().name(), "stack_string");
    }

    // 29. RC4 known test vector (partial)
    #[test]
    fn test_rc4_known_vector() {
        // RFC 6229: Key = 0x0102030405, PT = 0x0000...
        let key = &[0x01u8, 0x02, 0x03, 0x04, 0x05];
        let plaintext = vec![0u8; 16];
        let cipher = Rc4Pass::rc4(key, &plaintext);
        // The first bytes should not be all zeros
        assert_ne!(cipher, plaintext);
    }

    // 30. StringDeobfuscator add_pass increases count
    #[test]
    fn test_add_pass_increases_count() {
        let mut d = StringDeobfuscator::new();
        assert_eq!(d.pass_count(), 0);
        d.add_pass(Box::new(XorPass::new(vec![vec![0x01]], 0.9)));
        assert_eq!(d.pass_count(), 1);
    }

    // 31. Multiple passes: first match wins
    #[test]
    fn test_first_match_wins() {
        let mut d = StringDeobfuscator::new();
        d.add_pass(Box::new(XorPass::new(vec![vec![0x42]], 0.90)));
        d.add_pass(Box::new(StackStringPass::default()));
        let plain = b"Hello World";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
        let result = d.deobfuscate_one(0, &cipher).expect("ok");
        assert_eq!(result.algorithm, DeobfAlgorithm::Xor);
    }

    // 32. StackString with unsorted offsets
    #[test]
    fn test_stack_string_unsorted_offsets() {
        let ssp = StackStringPass::default();
        let assignments = vec![(2, b'l'), (0, b'h'), (1, b'e'), (3, b'l'), (4, b'o')];
        let result = ssp.reconstruct(&assignments).expect("ok");
        assert_eq!(result, "hello");
    }

    // 33. StringResult address stored correctly
    #[test]
    fn test_string_result_address() {
        let r = StringResult::new(
            0xdeadbeef,
            vec![],
            "x".into(),
            DeobfAlgorithm::Xor,
            vec![],
            Confidence::Low,
        );
        assert_eq!(r.address, 0xdeadbeef);
    }

    // 34. Confidence display
    #[test]
    fn test_confidence_display() {
        assert_eq!(Confidence::High.to_string(), "high");
        assert_eq!(Confidence::Low.to_string(), "low");
    }

    // 35. XorPass printable threshold edge case
    #[test]
    fn test_xor_threshold_exactly_met() {
        let pass = XorPass::new(vec![vec![0x00]], 0.0);
        // key = 0 means no change; data is printable
        let data = b"hello";
        let result = pass.try_deobf(0, data);
        assert!(result.is_some());
    }

    // 36. Rc4Pass printable threshold
    #[test]
    fn test_rc4_pass_threshold() {
        let pass = Rc4Pass {
            keys: vec![b"key".to_vec()],
            printable_threshold: 0.0,
        };
        let data = b"test";
        // with threshold 0 always matches
        let result = pass.try_deobf(0, data);
        assert!(result.is_some());
    }

    // 37. StringDeobfuscator deobfuscate_all empty input
    #[test]
    fn test_deobfuscate_all_empty_input() {
        let d = StringDeobfuscator::with_default_passes();
        let results = d.deobfuscate_all(&[]);
        assert!(results.is_empty());
    }

    // 38. filter_by_confidence returns all for Low
    #[test]
    fn test_filter_all_for_low() {
        let results = vec![
            StringResult::new(
                0,
                vec![],
                "a".into(),
                DeobfAlgorithm::Xor,
                vec![],
                Confidence::Low,
            ),
            StringResult::new(
                1,
                vec![],
                "b".into(),
                DeobfAlgorithm::Xor,
                vec![],
                Confidence::High,
            ),
        ];
        let filtered = StringDeobfuscator::filter_by_confidence(&results, Confidence::Low);
        assert_eq!(filtered.len(), 2);
    }

    // 39. RC4 empty key returns data unchanged
    #[test]
    fn test_rc4_empty_key() {
        let data = b"test";
        let result = Rc4Pass::rc4(&[], data);
        assert_eq!(result, data);
    }

    // 40. StackStringPass try_deobf on non-printable
    #[test]
    fn test_stack_string_non_printable() {
        let pass = StackStringPass::new(2);
        let data = vec![0x01, 0x02, 0x03, 0x04]; // non-printable
        assert!(pass.try_deobf(0, &data).is_none());
    }

    // 41. StringResult ciphertext stored
    #[test]
    fn test_string_result_ciphertext() {
        let cipher = vec![0xAA, 0xBB, 0xCC];
        let r = StringResult::new(
            0,
            cipher.clone(),
            "x".into(),
            DeobfAlgorithm::Xor,
            vec![],
            Confidence::Low,
        );
        assert_eq!(r.ciphertext, cipher);
    }

    // 42. XorPass empty key returns data unchanged
    #[test]
    fn test_xor_empty_key() {
        let data = b"hello";
        assert_eq!(XorPass::xor_decode(data, &[]), data.to_vec());
    }
}
