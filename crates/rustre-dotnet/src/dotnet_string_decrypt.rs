//! .NET string-decryption pattern detector and XOR-based decryptor.
//!
//! Many .NET obfuscators store encrypted strings in a byte-array field and
//! decrypt them at runtime via a helper method that takes an integer key.
//! This module detects these patterns in the decoded CIL instruction stream,
//! extracts the encrypted payload, and attempts XOR-based decryption.
//!
//! Types: [`EncryptedStrTable`], [`DecryptionMethod`], [`IntKey`],
//! [`XorDecryptor`], [`DecryptedResult`], [`StringDecryptScanner`].

use std::collections::HashMap;
use std::fmt;

// ─── EncryptedStrTable ────────────────────────────────────────────────────────

/// A raw encrypted string table extracted from a static byte-array field.
#[derive(Debug, Clone)]
pub struct EncryptedStrTable {
    /// The raw byte data of the encrypted table.
    pub data: Vec<u8>,
    /// Field token (RID) that holds this data (0 if unknown).
    pub field_token: u32,
    /// Byte offset within the PE image where this data was found.
    pub image_offset: u64,
}

impl EncryptedStrTable {
    #[must_use]
    pub const fn new(data: Vec<u8>, field_token: u32, image_offset: u64) -> Self {
        Self { data, field_token, image_offset }
    }

    /// Read a little-endian `u32` at byte `offset` within the table data.
    #[must_use]
    pub fn read_u32(&self, offset: usize) -> Option<u32> {
        if offset + 4 > self.data.len() { return None; }
        Some(u32::from_le_bytes(self.data[offset..offset+4].try_into().ok()?))
    }

    /// Read a little-endian `u16` at byte `offset`.
    #[must_use]
    pub fn read_u16(&self, offset: usize) -> Option<u16> {
        if offset + 2 > self.data.len() { return None; }
        Some(u16::from_le_bytes(self.data[offset..offset+2].try_into().ok()?))
    }

    /// Byte slice `[start, start+len)` from the table.
    #[must_use]
    pub fn slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        if start + len > self.data.len() { return None; }
        Some(&self.data[start..start+len])
    }

    /// Size of the table in bytes.
    #[must_use]
    pub const fn len(&self) -> usize { self.data.len() }

    /// True if the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.data.is_empty() }
}

impl fmt::Display for EncryptedStrTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedStrTable(token={:#x}, {} bytes @ {:#x})",
               self.field_token, self.data.len(), self.image_offset)
    }
}

// ─── DecryptionMethod ─────────────────────────────────────────────────────────

/// Metadata about a decryption helper method (the target of the `call` in
/// the encrypted-string pattern).
#[derive(Debug, Clone)]
pub struct DecryptionMethod {
    /// Method token (`MethodDef` or `MemberRef` RID).
    pub token: u32,
    /// Method name.
    pub name: String,
    /// Index of the integer-key parameter (0-based).
    pub key_param_index: u32,
    /// Whether the method is static.
    pub is_static: bool,
    /// Estimated number of parameters (not counting `this`).
    pub param_count: u32,
}

impl DecryptionMethod {
    #[must_use]
    pub fn new(token: u32, name: impl Into<String>, key_param_index: u32,
               is_static: bool, param_count: u32) -> Self {
        Self { token, name: name.into(), key_param_index, is_static, param_count }
    }
}

impl fmt::Display for DecryptionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecryptionMethod({}, token={:#x}, key_param={})",
               self.name, self.token, self.key_param_index)
    }
}

// ─── IntKey ───────────────────────────────────────────────────────────────────

/// An integer key passed to a decryption call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntKey {
    /// CIL offset of the `ldc.i4` instruction.
    pub offset: u32,
    /// The integer value.
    pub value: i32,
    /// CIL offset of the `call` instruction that uses this key.
    pub call_site: u32,
}

impl IntKey {
    #[must_use]
    pub const fn new(offset: u32, value: i32, call_site: u32) -> Self {
        Self { offset, value, call_site }
    }
}

impl fmt::Display for IntKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntKey({} @ IL_{:#x}, call @ IL_{:#x})",
               self.value, self.offset, self.call_site)
    }
}

// ─── DecryptedResult ─────────────────────────────────────────────────────────

/// The result of one decryption attempt.
#[derive(Debug, Clone)]
pub struct DecryptedResult {
    /// The integer key used.
    pub key: i32,
    /// The decrypted string (UTF-8).
    pub plaintext: String,
    /// The raw decrypted bytes (for non-UTF-8 content).
    pub raw_bytes: Vec<u8>,
    /// Confidence that this is correct (0.0 = no confidence, 1.0 = certain).
    pub confidence: f64,
    /// CIL offset of the call site where this key was passed.
    pub call_site: u32,
}

impl DecryptedResult {
    #[must_use]
    pub const fn new(key: i32, plaintext: String, raw_bytes: Vec<u8>,
               confidence: f64, call_site: u32) -> Self {
        Self { key, plaintext, raw_bytes, confidence, call_site }
    }

    /// True if the confidence is high enough to trust the result.
    #[must_use]
    pub fn is_reliable(&self) -> bool { self.confidence >= 0.7 }

    /// True if the decrypted content looks like printable ASCII.
    #[must_use]
    pub fn is_printable_ascii(&self) -> bool {
        self.raw_bytes.iter().all(|&b| (0x20..0x7F).contains(&b))
    }
}

impl fmt::Display for DecryptedResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[key={} conf={:.2}] {:?}", self.key, self.confidence, self.plaintext)
    }
}

// ─── XorDecryptor ─────────────────────────────────────────────────────────────

/// Decrypts strings from an encrypted table using XOR.
///
/// The most common obfuscator layout:
/// - Table layout: `[u32 length][encrypted_utf16_bytes...]`
/// - Key derivation: `xor_key ^ (offset as u32)` or constant XOR.
pub struct XorDecryptor<'a> {
    table: &'a [u8],
    xor_key: u32,
}

impl<'a> XorDecryptor<'a> {
    #[must_use]
    pub const fn new(table: &'a [u8], xor_key: u32) -> Self {
        Self { table, xor_key }
    }

    /// Decrypt the entry at `offset` within the table.
    ///
    /// Assumes layout: `u32 length_in_chars` followed by `length * 2` bytes
    /// (little-endian UTF-16).
    #[must_use]
    pub fn decrypt_at(&self, offset: usize) -> Option<DecryptedResult> {
        if offset + 4 > self.table.len() { return None; }
        let raw_len = u32::from_le_bytes(self.table[offset..offset+4].try_into().ok()?) as usize;
        let byte_len = raw_len * 2;
        let data_start = offset + 4;
        if data_start + byte_len > self.table.len() { return None; }

        let encrypted = &self.table[data_start..data_start + byte_len];
        let decrypted_bytes: Vec<u8> = encrypted.iter()
            .map(|&b| {
                let k = (self.xor_key & 0xFF) as u8;
                b ^ k
            })
            .collect();

        // Decode UTF-16LE.
        let u16_words: Vec<u16> = decrypted_bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let plaintext = String::from_utf16_lossy(&u16_words);
        let confidence = compute_string_confidence(&plaintext);

        Some(DecryptedResult::new(i32::try_from(offset).unwrap_or(i32::MAX), plaintext, decrypted_bytes, confidence, 0))
    }

    /// Decrypt using integer key as a flat XOR with key-derived shift.
    ///
    /// Pattern: each byte at table[key * 2 + i] XOR (`xor_key` >> (8*(i%4))).
    #[must_use]
    pub fn decrypt_key(&self, key: i32) -> Option<DecryptedResult> {
        let base = usize::try_from(key).ok()?.checked_mul(2)?;
        if base + 2 > self.table.len() { return None; }

        // Read encoded length at base.
        let enc_len = u16::from_le_bytes(self.table[base..base+2].try_into().ok()?) as usize;
        let data_start = base + 2;
        let byte_len = enc_len * 2;
        if data_start + byte_len > self.table.len() { return None; }

        let encrypted = &self.table[data_start..data_start + byte_len];
        let decrypted_bytes: Vec<u8> = encrypted.iter().enumerate()
            .map(|(i, &b)| {
                let shift = (i % 4) * 8;
                let k = ((self.xor_key >> shift) & 0xFF) as u8;
                b ^ k
            })
            .collect();

        let u16_words: Vec<u16> = decrypted_bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let plaintext = String::from_utf16_lossy(&u16_words);
        let confidence = compute_string_confidence(&plaintext);

        Some(DecryptedResult::new(key, plaintext, decrypted_bytes, confidence, 0))
    }

    /// Try all known XOR keys and return the best result for a given offset.
    #[must_use]
    pub fn brute_force_xor_key(&self, offset: usize, candidates: &[u32]) -> Option<DecryptedResult> {
        candidates.iter()
            .filter_map(|&k| {
                let d = XorDecryptor::new(self.table, k);
                d.decrypt_at(offset)
            })
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }
}

/// Heuristic: score how likely `s` is a real human-readable string.
fn compute_string_confidence(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let printable = s.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').count();
    let char_count = s.chars().count();
    let ratio = f64::from(u32::try_from(printable).unwrap_or(u32::MAX)) / f64::from(u32::try_from(char_count).unwrap_or(1));
    // Boost for ASCII alphanumeric content.
    let ascii_alpha = s.chars().filter(|c| c.is_ascii_alphanumeric() || " .,;:!?-_/\\".contains(*c)).count();
    let ascii_ratio = f64::from(u32::try_from(ascii_alpha).unwrap_or(u32::MAX)) / f64::from(u32::try_from(char_count).unwrap_or(1));
    ratio.mul_add(0.5, ascii_ratio * 0.5).min(1.0)
}

// ─── PatternMatch ─────────────────────────────────────────────────────────────

/// A detected encrypted-string call site in CIL.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// CIL offset of the `ldc.i4` (key push).
    pub key_offset: u32,
    /// The integer key value.
    pub key_value: i32,
    /// CIL offset of the `call` instruction.
    pub call_offset: u32,
    /// Method token of the callee.
    pub callee_token: u32,
}

impl fmt::Display for PatternMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PatternMatch(key={} @ IL_{:#x}, call @ IL_{:#x}, callee={:#x})",
               self.key_value, self.key_offset, self.call_offset, self.callee_token)
    }
}

// ─── StringDecryptScanner ─────────────────────────────────────────────────────

/// Scans a CIL instruction stream for encrypted-string call-site patterns.
///
/// Pattern: `ldc.i4 <key>` immediately followed by `call <decryptor_token>`.
/// The scanner is configurable so it can match multiple decryptor tokens.
pub struct StringDecryptScanner {
    /// Tokens of known decryption methods.
    target_tokens: Vec<u32>,
}

impl StringDecryptScanner {
    #[must_use]
    pub const fn new() -> Self {
        Self { target_tokens: Vec::new() }
    }

    /// Register a method token as a decryption callee.
    pub fn add_target(&mut self, token: u32) {
        if !self.target_tokens.contains(&token) {
            self.target_tokens.push(token);
        }
    }

    /// Scan `insns` for `ldc.i4 <key>` + `call <target>` patterns.
    ///
    /// `insns` is a sequence of `(offset, mnemonic, operand_i32, method_token)` tuples
    /// — a simplified view of the full instruction stream.
    #[must_use]
    pub fn scan(&self, insns: &[RawCilInsn]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let ldc_mnemonics = [
            "ldc.i4", "ldc.i4.s", "ldc.i4.0", "ldc.i4.1", "ldc.i4.2",
            "ldc.i4.3", "ldc.i4.4", "ldc.i4.5", "ldc.i4.6", "ldc.i4.7",
            "ldc.i4.8", "ldc.i4.m1",
        ];

        for i in 0..insns.len().saturating_sub(1) {
            let cur = &insns[i];
            let next = &insns[i + 1];

            if !ldc_mnemonics.contains(&cur.mnemonic.as_str()) { continue; }
            if next.mnemonic != "call" && next.mnemonic != "callvirt" { continue; }
            if !self.target_tokens.is_empty() && !self.target_tokens.contains(&next.method_token) {
                continue;
            }

            matches.push(PatternMatch {
                key_offset: cur.offset,
                key_value: cur.int_operand,
                call_offset: next.offset,
                callee_token: next.method_token,
            });
        }
        matches
    }

    /// Scan and also attempt decryption via `decryptor`.
    #[must_use]
    pub fn scan_and_decrypt(
        &self,
        insns: &[RawCilInsn],
        decryptor: &XorDecryptor<'_>,
    ) -> Vec<(PatternMatch, Option<DecryptedResult>)> {
        let matches = self.scan(insns);
        matches.into_iter()
            .map(|m| {
                let key = m.key_value;
                let mut result = decryptor.decrypt_key(key);
                if let Some(ref mut r) = result {
                    r.call_site = m.call_offset;
                }
                (m, result)
            })
            .collect()
    }
}

impl Default for StringDecryptScanner {
    fn default() -> Self { Self::new() }
}

/// A simplified CIL instruction view for pattern scanning.
#[derive(Debug, Clone)]
pub struct RawCilInsn {
    pub offset: u32,
    pub mnemonic: String,
    /// Integer operand (meaningful for ldc.i4 family).
    pub int_operand: i32,
    /// Method token (meaningful for call/callvirt).
    pub method_token: u32,
}

impl RawCilInsn {
    #[must_use]
    pub fn new(offset: u32, mnemonic: impl Into<String>) -> Self {
        Self { offset, mnemonic: mnemonic.into(), int_operand: 0, method_token: 0 }
    }

    #[must_use]
    pub fn ldc_i4(offset: u32, value: i32) -> Self {
        Self { offset, mnemonic: "ldc.i4".into(), int_operand: value, method_token: 0 }
    }

    #[must_use]
    pub fn call(offset: u32, token: u32) -> Self {
        Self { offset, mnemonic: "call".into(), int_operand: 0, method_token: token }
    }
}

// ─── EncryptedStringCatalog ───────────────────────────────────────────────────

/// A collected catalog of all decrypted strings for a single method / assembly.
#[derive(Debug, Default)]
pub struct EncryptedStringCatalog {
    /// key → decrypted string.
    entries: HashMap<i32, DecryptedResult>,
}

impl EncryptedStringCatalog {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Insert a decrypted result (keeps the higher-confidence entry on conflict).
    pub fn insert(&mut self, result: DecryptedResult) {
        let entry = self.entries.entry(result.key).or_insert_with(|| result.clone());
        if result.confidence > entry.confidence {
            *entry = result;
        }
    }

    /// Look up a decrypted string by integer key.
    #[must_use]
    pub fn lookup(&self, key: i32) -> Option<&str> {
        self.entries.get(&key).map(|r| r.plaintext.as_str())
    }

    /// Total number of entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// All entries sorted by key.
    #[must_use]
    pub fn sorted_entries(&self) -> Vec<&DecryptedResult> {
        let mut v: Vec<&DecryptedResult> = self.entries.values().collect();
        v.sort_by_key(|r| r.key);
        v
    }

    /// Export as CSV: `key,confidence,plaintext`.
    #[must_use]
    pub fn export_csv(&self) -> String {
        use std::fmt::Write as FmtWrite;
        let mut out = String::from("key,confidence,plaintext\n");
        for r in self.sorted_entries() {
            writeln!(out, "{},{:.3},{}", r.key, r.confidence,
                     r.plaintext.replace(',', "\\,").replace('\n', "\\n"))
                .expect("writing to String never fails");
        }
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EncryptedStrTable ──────────────────────────────────────────────────────

    #[test]
    fn encrypted_str_table_read_u32() {
        let data = vec![0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12];
        let t = EncryptedStrTable::new(data, 0, 0);
        assert_eq!(t.read_u32(4), Some(0x1234_5678));
        assert_eq!(t.read_u32(6), None);
    }

    #[test]
    fn encrypted_str_table_slice() {
        let data = vec![1u8, 2, 3, 4, 5];
        let t = EncryptedStrTable::new(data, 0, 0);
        assert_eq!(t.slice(1, 3), Some(&[2u8, 3, 4][..]));
        assert_eq!(t.slice(4, 2), None);
    }

    #[test]
    fn encrypted_str_table_display() {
        let t = EncryptedStrTable::new(vec![0u8; 10], 0x0400_0001, 0x200);
        let s = t.to_string();
        assert!(s.contains("10 bytes"));
    }

    // ── XorDecryptor ──────────────────────────────────────────────────────────

    fn make_utf16_le_entry(s: &str) -> Vec<u8> {
        let chars: Vec<u16> = s.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&(chars.len() as u32).to_le_bytes());
        for c in &chars {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    #[test]
    fn xor_decrypt_zero_key() {
        // XOR key = 0 means identity decrypt for key-index 0.
        let s = "Hello";
        let entry = make_utf16_le_entry(s);
        let decryptor = XorDecryptor::new(&entry, 0);
        let result = decryptor.decrypt_at(0).unwrap();
        assert_eq!(result.plaintext, "Hello");
    }

    #[test]
    fn xor_decrypt_at_truncated() {
        let data = vec![0x05u8]; // length 5 but no data
        let d = XorDecryptor::new(&data, 0);
        assert!(d.decrypt_at(0).is_none());
    }

    #[test]
    fn xor_decrypt_empty_table() {
        let d = XorDecryptor::new(&[], 0);
        assert!(d.decrypt_at(0).is_none());
    }

    // ── PatternMatch scanning ─────────────────────────────────────────────────

    #[test]
    fn scan_finds_pattern() {
        let insns = vec![
            RawCilInsn::ldc_i4(0, 42),
            RawCilInsn::call(1, 0x0600_0001),
        ];
        let mut scanner = StringDecryptScanner::new();
        scanner.add_target(0x0600_0001);
        let matches = scanner.scan(&insns);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key_value, 42);
    }

    #[test]
    fn scan_no_match_wrong_token() {
        let insns = vec![
            RawCilInsn::ldc_i4(0, 7),
            RawCilInsn::call(1, 0x0600_9999),
        ];
        let mut scanner = StringDecryptScanner::new();
        scanner.add_target(0x0600_0001);
        let matches = scanner.scan(&insns);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_any_token_when_no_targets() {
        let insns = vec![
            RawCilInsn::ldc_i4(0, 3),
            RawCilInsn::call(1, 0xABCD),
        ];
        let scanner = StringDecryptScanner::new(); // no target tokens registered
        let matches = scanner.scan(&insns);
        // With no registered targets, all calls match.
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn scan_requires_ldc_before_call() {
        let insns = vec![
            RawCilInsn::call(0, 0x01),
            RawCilInsn::ldc_i4(5, 1),
        ];
        let scanner = StringDecryptScanner::new();
        let matches = scanner.scan(&insns);
        assert!(matches.is_empty());
    }

    // ── DecryptedResult ───────────────────────────────────────────────────────

    #[test]
    fn decrypted_result_reliable() {
        let r = DecryptedResult::new(0, "hello world".into(), b"hello world".to_vec(), 0.95, 0);
        assert!(r.is_reliable());
    }

    #[test]
    fn decrypted_result_not_reliable() {
        let r = DecryptedResult::new(0, String::new(), vec![], 0.3, 0);
        assert!(!r.is_reliable());
    }

    #[test]
    fn decrypted_result_printable() {
        let r = DecryptedResult::new(0, "abc".into(), b"abc".to_vec(), 1.0, 0);
        assert!(r.is_printable_ascii());
    }

    #[test]
    fn decrypted_result_not_printable() {
        let r = DecryptedResult::new(0, String::new(), vec![0x00, 0xFF, 0x80], 0.5, 0);
        assert!(!r.is_printable_ascii());
    }

    // ── EncryptedStringCatalog ────────────────────────────────────────────────

    #[test]
    fn catalog_insert_and_lookup() {
        let mut cat = EncryptedStringCatalog::new();
        cat.insert(DecryptedResult::new(1, "foo".into(), b"foo".to_vec(), 0.9, 0));
        assert_eq!(cat.lookup(1), Some("foo"));
        assert_eq!(cat.lookup(2), None);
    }

    #[test]
    fn catalog_keeps_higher_confidence() {
        let mut cat = EncryptedStringCatalog::new();
        cat.insert(DecryptedResult::new(5, "low".into(), b"low".to_vec(), 0.3, 0));
        cat.insert(DecryptedResult::new(5, "high".into(), b"high".to_vec(), 0.9, 0));
        assert_eq!(cat.lookup(5), Some("high"));
    }

    #[test]
    fn catalog_export_csv() {
        let mut cat = EncryptedStringCatalog::new();
        cat.insert(DecryptedResult::new(0, "test".into(), b"test".to_vec(), 1.0, 0));
        let csv = cat.export_csv();
        assert!(csv.contains("key,confidence,plaintext"));
        assert!(csv.contains("test"));
    }

    #[test]
    fn compute_string_confidence_empty() {
        assert_eq!(compute_string_confidence(""), 0.0);
    }

    #[test]
    fn compute_string_confidence_ascii_text() {
        let c = compute_string_confidence("Hello, world!");
        assert!(c > 0.7, "confidence should be high for printable ASCII: {c}");
    }

    #[test]
    fn decryption_method_display() {
        let m = DecryptionMethod::new(0x0600_0001, "DecryptString", 0, true, 1);
        assert!(m.to_string().contains("DecryptString"));
    }

    #[test]
    fn int_key_display() {
        let k = IntKey::new(0x10, 42, 0x15);
        assert!(k.to_string().contains("42"));
    }

    #[test]
    fn pattern_match_display() {
        let m = PatternMatch { key_offset: 0, key_value: 5, call_offset: 1, callee_token: 0xABCD };
        assert!(m.to_string().contains('5'));
    }
}
