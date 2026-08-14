//! DEX string pool: parse the string ID list, read UTF-16 encoded string data,
//! and provide fast pool lookup by index.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Parsing error
// ---------------------------------------------------------------------------

/// Error type for string pool parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StringPoolError {
    #[error("buffer too short at offset {0}")]
    TooShort(usize),
    #[error("invalid ULEB128 at offset {0}")]
    InvalidUleb128(usize),
    #[error("invalid UTF-8 in string at index {0}")]
    InvalidUtf8(usize),
    #[error("string index {0} out of range (pool size {1})")]
    IndexOutOfRange(usize, usize),
    #[error("malformed MUTF-8 sequence at offset {0}")]
    MalformedMutf8(usize),
}

// ---------------------------------------------------------------------------
// ULEB128 reader
// ---------------------------------------------------------------------------

/// Decode an unsigned LEB128 value from `data[offset..]`.
/// Returns `(value, bytes_consumed)`.
fn read_uleb128(data: &[u8], offset: usize) -> Result<(u32, usize), StringPoolError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            return Err(StringPoolError::InvalidUleb128(offset));
        }
        let byte = data[pos];
        pos += 1;
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return Err(StringPoolError::InvalidUleb128(offset));
        }
    }
    Ok((result, pos - offset))
}

// ---------------------------------------------------------------------------
// MUTF-8 decoder
// ---------------------------------------------------------------------------

/// Decode a Modified-UTF-8 (MUTF-8) string as used in the DEX format.
///
/// MUTF-8 is identical to CESU-8 with the additional property that the null
/// character (U+0000) is encoded as the two-byte sequence `0xC0 0x80` rather
/// than a single null byte.
fn decode_mutf8(bytes: &[u8]) -> Result<String, StringPoolError> {
    let mut chars = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    let offset = 0usize;

    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 == 0 {
            // Null terminator
            break;
        }
        if b0 & 0x80 == 0 {
            // Single-byte ASCII
            chars.push(b0 as char);
            i += 1;
        } else if b0 & 0xE0 == 0xC0 {
            // Two-byte sequence
            if i + 1 >= bytes.len() {
                return Err(StringPoolError::MalformedMutf8(offset + i));
            }
            let b1 = bytes[i + 1];
            let code = (u32::from(b0 & 0x1F) << 6) | u32::from(b1 & 0x3F);
            // U+0000 encoded as 0xC0 0x80
            let ch = char::from_u32(code).unwrap_or('\u{FFFD}');
            chars.push(ch);
            i += 2;
        } else if b0 & 0xF0 == 0xE0 {
            // Three-byte sequence
            if i + 2 >= bytes.len() {
                return Err(StringPoolError::MalformedMutf8(offset + i));
            }
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            let code = (u32::from(b0 & 0x0F) << 12)
                | (u32::from(b1 & 0x3F) << 6)
                | u32::from(b2 & 0x3F);
            let ch = char::from_u32(code).unwrap_or('\u{FFFD}');
            chars.push(ch);
            i += 3;
        } else {
            // Invalid or 4-byte sequence (not valid in MUTF-8)
            return Err(StringPoolError::MalformedMutf8(offset + i));
        }
    }
    Ok(chars.iter().collect())
}

// ---------------------------------------------------------------------------
// StringId
// ---------------------------------------------------------------------------

/// A DEX string ID: the file offset of the corresponding string data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StringId {
    /// Index in the string ID list.
    pub index: u32,
    /// File offset of the `string_data_item`.
    pub data_offset: u32,
}

impl StringId {
    /// Create a new string ID.
    #[must_use]
    pub const fn new(index: u32, data_offset: u32) -> Self {
        Self { index, data_offset }
    }
}

impl std::fmt::Display for StringId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StringId(index={}, data_off={:#x})",
            self.index, self.data_offset
        )
    }
}

// ---------------------------------------------------------------------------
// DexString
// ---------------------------------------------------------------------------

/// A decoded string from the DEX string pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DexString {
    /// The decoded string value.
    pub value: String,
    /// UTF-16 length (in code units, as stored in the DEX header).
    pub utf16_size: u32,
    /// The source string ID.
    pub string_id: StringId,
}

impl DexString {
    /// Whether this string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Whether this string looks like a fully-qualified class descriptor
    /// (starts with `L` and ends with `;`).
    #[must_use]
    pub fn is_class_descriptor(&self) -> bool {
        self.value.starts_with('L') && self.value.ends_with(';')
    }

    /// Whether this string looks like a method descriptor (starts with `(`).
    #[must_use]
    pub fn is_method_descriptor(&self) -> bool {
        self.value.starts_with('(')
    }

    /// Whether this string is a primitive type descriptor (`V`, `I`, `Z`, etc.).
    #[must_use]
    pub fn is_primitive_descriptor(&self) -> bool {
        matches!(
            self.value.as_str(),
            "V" | "Z" | "B" | "S" | "C" | "I" | "J" | "F" | "D"
        )
    }
}

impl std::fmt::Display for DexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.value)
    }
}

// ---------------------------------------------------------------------------
// DexStringPool
// ---------------------------------------------------------------------------

/// Parsed DEX string pool.
///
/// Contains all decoded strings, indexed by their string ID.
/// The DEX format stores strings as MUTF-8 data items referenced from a
/// sorted list of string IDs (each a 4-byte offset).
pub struct DexStringPool {
    /// The decoded strings in index order.
    strings: Vec<DexString>,
    /// Reverse lookup: string value -> list of indices
    value_to_indices: HashMap<String, Vec<u32>>,
}

impl DexStringPool {
    /// Parse the string pool from raw DEX file bytes.
    ///
    /// - `data`: entire DEX file byte slice
    /// - `string_ids_offset`: file offset of the string ID list
    /// - `string_ids_size`: number of string IDs
    ///
    /// # Errors
    ///
    /// Returns a `StringPoolError` on malformed data.
    pub fn parse(
        data: &[u8],
        string_ids_offset: u32,
        string_ids_size: u32,
    ) -> Result<Self, StringPoolError> {
        // Cap the pre-allocation to what can physically fit in the data buffer.
        // Each string ID entry is 4 bytes, so the data can hold at most
        // `data.len() / 4` entries. Without this cap an attacker can provide
        // `string_ids_size = 0xFFFF_FFFF` and cause a multi-GB allocation before
        // any bounds check is reached (dos-memory-exhaustion).
        let safe_capacity = (string_ids_size as usize).min(data.len() / 4);
        let mut strings = Vec::with_capacity(safe_capacity);
        let mut value_to_indices: HashMap<String, Vec<u32>> = HashMap::new();

        let ids_off = string_ids_offset as usize;
        let ids_count = string_ids_size as usize;

        for i in 0..ids_count {
            let off = ids_off.checked_add(i.checked_mul(4).ok_or(StringPoolError::TooShort(ids_off))?)
                .ok_or(StringPoolError::TooShort(ids_off))?;
            if off + 4 > data.len() {
                return Err(StringPoolError::TooShort(off));
            }
            let data_offset = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            let sid = StringId::new(i as u32, data_offset);

            let data_off = data_offset as usize;
            if data_off >= data.len() {
                return Err(StringPoolError::TooShort(data_off));
            }

            // Read ULEB128 utf16_size
            let (utf16_size, consumed) = read_uleb128(data, data_off)?;
            let string_data_start = data_off
                .checked_add(consumed)
                .ok_or(StringPoolError::TooShort(data_off))?;
            if string_data_start > data.len() {
                return Err(StringPoolError::TooShort(string_data_start));
            }

            // Read until null terminator or end of buffer
            let string_data_end = data[string_data_start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |p| string_data_start + p);

            let string_bytes = &data[string_data_start..string_data_end];
            let value = decode_mutf8(string_bytes)?;

            value_to_indices.entry(value.clone()).or_default().push(i as u32);
            strings.push(DexString {
                value,
                utf16_size,
                string_id: sid,
            });
        }

        Ok(Self {
            strings,
            value_to_indices,
        })
    }

    /// Create a pool directly from a list of string values (for testing).
    #[must_use]
    pub fn from_values(values: Vec<String>) -> Self {
        let mut value_to_indices: HashMap<String, Vec<u32>> = HashMap::new();
        let strings: Vec<DexString> = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                value_to_indices
                    .entry(v.clone())
                    .or_default()
                    .push(i as u32);
                let utf16_len = v.encode_utf16().count() as u32;
                DexString {
                    utf16_size: utf16_len,
                    string_id: StringId::new(i as u32, 0),
                    value: v,
                }
            })
            .collect();
        Self {
            strings,
            value_to_indices,
        }
    }

    /// Look up a string by its index.
    ///
    /// # Errors
    ///
    /// Returns `StringPoolError::IndexOutOfRange` if `index >= pool size`.
    pub fn get(&self, index: usize) -> Result<&DexString, StringPoolError> {
        self.strings
            .get(index)
            .ok_or(StringPoolError::IndexOutOfRange(index, self.strings.len()))
    }

    /// Look up a string by index, returning `None` instead of an error.
    #[must_use]
    pub fn get_opt(&self, index: usize) -> Option<&DexString> {
        self.strings.get(index)
    }

    /// Return the string value for `index`, or `None`.
    #[must_use]
    pub fn value_at(&self, index: usize) -> Option<&str> {
        self.strings.get(index).map(|s| s.value.as_str())
    }

    /// Find all indices of strings with value `value`.
    #[must_use]
    pub fn find(&self, value: &str) -> &[u32] {
        self.value_to_indices
            .get(value)
            .map_or(&[], Vec::as_slice)
    }

    /// Whether the pool contains `value`.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.value_to_indices.contains_key(value)
    }

    /// Number of strings in the pool.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Iterate over all strings in index order.
    pub fn iter(&self) -> impl Iterator<Item = &DexString> {
        self.strings.iter()
    }

    /// Return all strings that look like class descriptors.
    #[must_use]
    pub fn class_descriptors(&self) -> Vec<&DexString> {
        self.strings.iter().filter(|s| s.is_class_descriptor()).collect()
    }

    /// Return all strings that look like method descriptors.
    #[must_use]
    pub fn method_descriptors(&self) -> Vec<&DexString> {
        self.strings
            .iter()
            .filter(|s| s.is_method_descriptor())
            .collect()
    }

    /// Return all strings whose value starts with `prefix`.
    #[must_use]
    pub fn strings_with_prefix(&self, prefix: &str) -> Vec<&DexString> {
        self.strings
            .iter()
            .filter(|s| s.value.starts_with(prefix))
            .collect()
    }

    /// Return all strings sorted alphabetically by value.
    #[must_use]
    pub fn sorted_by_value(&self) -> Vec<&DexString> {
        let mut result: Vec<&DexString> = self.strings.iter().collect();
        result.sort_by(|a, b| a.value.cmp(&b.value));
        result
    }

    /// Return the most common string values (top N by frequency, for duplicates).
    #[must_use]
    pub fn most_common(&self, n: usize) -> Vec<(&str, usize)> {
        let mut counts: Vec<(&str, usize)> = self
            .value_to_indices
            .iter()
            .map(|(v, indices)| (v.as_str(), indices.len()))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(n);
        counts
    }

    /// Build a reverse-lookup table from UTF-16 size to indices.
    #[must_use]
    pub fn by_utf16_size(&self) -> HashMap<u32, Vec<u32>> {
        let mut map: HashMap<u32, Vec<u32>> = HashMap::new();
        for s in &self.strings {
            map.entry(s.utf16_size).or_default().push(s.string_id.index);
        }
        map
    }
}

impl std::fmt::Debug for DexStringPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DexStringPool")
            .field("count", &self.strings.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// StringIdListParser — parse just the raw ID list
// ---------------------------------------------------------------------------

/// Parse only the string ID list from a DEX file, returning raw (index, offset) pairs.
pub fn parse_string_id_list(
    data: &[u8],
    string_ids_offset: u32,
    string_ids_size: u32,
) -> Result<Vec<StringId>, StringPoolError> {
    let ids_off = string_ids_offset as usize;
    let ids_count = string_ids_size as usize;
    // Cap pre-allocation to what the buffer can physically hold to prevent
    // a dos-memory-exhaustion attack via a crafted string_ids_size header field.
    let safe_capacity = ids_count.min(data.len() / 4);
    let mut ids = Vec::with_capacity(safe_capacity);

    for i in 0..ids_count {
        let off = ids_off + i * 4;
        if off + 4 > data.len() {
            return Err(StringPoolError::TooShort(off));
        }
        let data_offset =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        ids.push(StringId::new(i as u32, data_offset));
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128_single_byte() {
        let data = [0x05u8];
        let (val, consumed) = read_uleb128(&data, 0).unwrap();
        assert_eq!(val, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_uleb128_multi_byte() {
        // 300 = 0x12C → ULEB128: 0xAC 0x02
        let data = [0xACu8, 0x02];
        let (val, consumed) = read_uleb128(&data, 0).unwrap();
        assert_eq!(val, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_mutf8_ascii() {
        let bytes = b"Hello";
        let s = decode_mutf8(bytes).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_decode_mutf8_null_encoding() {
        // U+0000 encoded as 0xC0 0x80
        let bytes = [0xC0u8, 0x80];
        let s = decode_mutf8(&bytes).unwrap();
        assert_eq!(s, "\u{0000}");
    }

    #[test]
    fn test_decode_mutf8_three_byte() {
        // U+4E2D (中) = 0xE4 0xB8 0xAD
        let bytes = [0xE4u8, 0xB8, 0xAD];
        let s = decode_mutf8(&bytes).unwrap();
        assert_eq!(s, "\u{4E2D}");
    }

    #[test]
    fn test_pool_from_values() {
        let pool = DexStringPool::from_values(vec![
            "Ljava/lang/Object;".to_owned(),
            "Ljava/lang/String;".to_owned(),
            "(I)V".to_owned(),
            "I".to_owned(),
        ]);

        assert_eq!(pool.len(), 4);
        assert_eq!(pool.value_at(0), Some("Ljava/lang/Object;"));
        assert!(pool.contains("Ljava/lang/String;"));
        assert!(!pool.contains("nonexistent"));
    }

    #[test]
    fn test_class_descriptors() {
        let pool = DexStringPool::from_values(vec![
            "Ljava/lang/Object;".to_owned(),
            "(I)V".to_owned(),
            "I".to_owned(),
            "Landroid/app/Activity;".to_owned(),
        ]);
        let descriptors = pool.class_descriptors();
        assert_eq!(descriptors.len(), 2);
    }

    #[test]
    fn test_method_descriptors() {
        let pool = DexStringPool::from_values(vec![
            "(I)V".to_owned(),
            "([BII)V".to_owned(),
            "Ljava/lang/String;".to_owned(),
        ]);
        let descs = pool.method_descriptors();
        assert_eq!(descs.len(), 2);
    }

    #[test]
    fn test_find_by_value() {
        let pool = DexStringPool::from_values(vec!["foo".to_owned(), "bar".to_owned(), "foo".to_owned()]);
        let indices = pool.find("foo");
        assert_eq!(indices.len(), 2);
    }

    #[test]
    fn test_pool_get_out_of_range() {
        let pool = DexStringPool::from_values(vec!["x".to_owned()]);
        assert!(pool.get(99).is_err());
    }

    #[test]
    fn test_strings_with_prefix() {
        let pool = DexStringPool::from_values(vec![
            "Ljava/lang/Object;".to_owned(),
            "Landroid/app/Activity;".to_owned(),
            "(I)V".to_owned(),
        ]);
        let java = pool.strings_with_prefix("Ljava/");
        assert_eq!(java.len(), 1);
    }

    #[test]
    fn test_sorted_by_value() {
        let pool = DexStringPool::from_values(vec!["c".to_owned(), "a".to_owned(), "b".to_owned()]);
        let sorted = pool.sorted_by_value();
        assert_eq!(sorted[0].value, "a");
        assert_eq!(sorted[1].value, "b");
        assert_eq!(sorted[2].value, "c");
    }

    #[test]
    fn test_is_primitive_descriptor() {
        let pool = DexStringPool::from_values(vec![
            "V".to_owned(),
            "I".to_owned(),
            "J".to_owned(),
            "Ljava/lang/String;".to_owned(),
        ]);
        assert!(pool.get(0).unwrap().is_primitive_descriptor());
        assert!(pool.get(1).unwrap().is_primitive_descriptor());
        assert!(!pool.get(3).unwrap().is_primitive_descriptor());
    }

    #[test]
    fn test_parse_string_pool_from_bytes() {
        // Build a minimal DEX-like byte blob:
        // StringID list at offset 0: two 4-byte offsets
        // String data at offsets 8 and 20
        let mut data = vec![0u8; 64];

        // String ID 0: offset 8
        data[0..4].copy_from_slice(&8u32.to_le_bytes());
        // String ID 1: offset 20
        data[4..8].copy_from_slice(&20u32.to_le_bytes());

        // String data 0 at offset 8: ULEB128(5) + "hello\0"
        data[8] = 5; // utf16_size = 5
        data[9..14].copy_from_slice(b"hello");
        data[14] = 0; // null terminator

        // String data 1 at offset 20: ULEB128(5) + "world\0"
        data[20] = 5; // utf16_size = 5
        data[21..26].copy_from_slice(b"world");
        data[26] = 0;

        let pool = DexStringPool::parse(&data, 0, 2).unwrap();
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.value_at(0), Some("hello"));
        assert_eq!(pool.value_at(1), Some("world"));
    }
}
