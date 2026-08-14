//! `rustre-mobile-ipa::plist_binary`
//!
//! **Low-level** binary plist (`bplist00`) format parser.
//!
//! # Design note — intentionally distinct from `plist_parser`
//!
//! [`crate::plist_parser`] is the **high-level** plist module: it handles both
//! binary and XML plists through a unified `PlistValue` enum and provides typed
//! accessors, dict traversal helpers, and XML serialisation.  Use it when you
//! need full plist semantics.
//!
//! This module (`plist_binary`) exposes the **raw binary-format internals**:
//! `BplistReader` gives direct access to the object table, offset table, and
//! trailer.  Use it when you need low-level inspection of the bplist structure
//! (e.g. debugging, fuzzing, or reading fields not surfaced by the high-level
//! parser).
//!
//! Binary plist (`bplist00`) format parser.
//!
//! Apple's binary plist format (magic `bplist00`) is a compact binary encoding
//! of a property list.  It consists of:
//! * A **magic** header (`bplist00`, 8 bytes).
//! * An **object table** — a flat array of encoded objects.
//! * An **offset table** — a flat array of byte offsets pointing into the
//!   object table.
//! * A **trailer** (32 bytes at the end of the file) with table metadata.
//!
//! # References
//! - CoreFoundation source: `CFBinaryPList.c`

pub use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// BplistError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the binary plist parser.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BplistError {
    #[error("data is too short (need at least {0} bytes, got {1})")]
    TooShort(usize, usize),
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("trailer parse error: {0}")]
    TrailerError(String),
    #[error("object decode error: {0}")]
    ObjectError(String),
    #[error("index {0} out of bounds (object count = {1})")]
    IndexOutOfBounds(usize, usize),
    #[error("unsupported object tag {0:#04x}")]
    UnsupportedTag(u8),
    #[error("integer overflow in length encoding")]
    IntegerOverflow,
}

// ─────────────────────────────────────────────────────────────────────────────
// BplistObject
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded binary plist value.
#[derive(Debug, Clone, PartialEq)]
pub enum BplistObject {
    /// `false` boolean.
    Bool(bool),
    /// Integer (stored as i64 to accommodate both signed and unsigned).
    Int(i64),
    /// Floating-point number.
    Real(f64),
    /// Date (seconds since 2001-01-01T00:00:00Z, the CF Absolute time epoch).
    Date(f64),
    /// Binary data.
    Data(Vec<u8>),
    /// UTF-8 or ASCII string.
    String(String),
    /// UTF-16 string (converted to Rust String).
    Utf16String(String),
    /// UID (used in `NSKeyedArchiver` plists).
    Uid(u64),
    /// Array of object indices (resolved to objects by the reader).
    Array(Vec<Self>),
    /// Dictionary (key objects → value objects).
    Dict(Vec<(Self, Self)>),
    /// Null value.
    Null,
}

impl BplistObject {
    /// Return a JSON-like representation of this object.
    #[must_use]
    pub fn to_json(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => n.to_string(),
            Self::Real(v) => format!("{v}"),
            Self::Date(v) => format!("\"<date: {v}>\""),
            Self::Data(d) => format!("\"<data: {} bytes>\"", d.len()),
            Self::String(s) | Self::Utf16String(s) => {
                let escaped = s.replace('"', "\\\"");
                format!("\"{escaped}\"")
            }
            Self::Uid(n) => format!("{{\"UID\": {n}}}"),
            Self::Null => "null".into(),
            Self::Array(a) => {
                let items: Vec<_> = a.iter().map(Self::to_json).collect();
                format!("[{}]", items.join(", "))
            }
            Self::Dict(d) => {
                let pairs: Vec<_> = d
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k.to_json(), v.to_json()))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
        }
    }

    /// Returns the string value if this is a `String` or `Utf16String`.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) | Self::Utf16String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the integer value if this is an `Int`.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        if let Self::Int(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    /// Returns the bool value if this is a `Bool`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Returns the array items if this is an `Array`.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        if let Self::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }

    /// Returns the dict items if this is a `Dict`.
    #[must_use]
    pub fn as_dict(&self) -> Option<&[(Self, Self)]> {
        if let Self::Dict(d) = self {
            Some(d)
        } else {
            None
        }
    }
}

impl std::fmt::Display for BplistObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_json())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trailer
// ─────────────────────────────────────────────────────────────────────────────

/// The 32-byte trailer at the end of every bplist00 file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BplistTrailer {
    /// Number of bytes used to store each offset in the offset table.
    pub offset_int_size: u8,
    /// Number of bytes used to store each object reference.
    pub object_ref_size: u8,
    /// Total number of objects in the object table.
    pub num_objects: u64,
    /// Index of the top-level object.
    pub top_object: u64,
    /// Byte offset of the offset table from the start of the file.
    pub offset_table_offset: u64,
}

impl BplistTrailer {
    /// Parse the 32-byte trailer.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        let t = &data[data.len() - 32..];
        // Bytes 0..5 are reserved (should be 0).
        let offset_int_size = t[6];
        let object_ref_size = t[7];
        let num_objects = u64::from_be_bytes(t[8..16].try_into().ok()?);
        let top_object = u64::from_be_bytes(t[16..24].try_into().ok()?);
        let offset_table_offset = u64::from_be_bytes(t[24..32].try_into().ok()?);
        Some(Self {
            offset_int_size,
            object_ref_size,
            num_objects,
            top_object,
            offset_table_offset,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OffsetTable
// ─────────────────────────────────────────────────────────────────────────────

/// The offset table that maps object indices to byte positions.
#[derive(Debug, Clone)]
pub struct OffsetTable {
    /// Offsets in order (index → byte position in the file).
    pub offsets: Vec<usize>,
}

impl OffsetTable {
    /// Parse the offset table from `data` given the trailer.
    #[must_use]
    pub fn parse(data: &[u8], trailer: &BplistTrailer) -> Option<Self> {
        let int_sz = trailer.offset_int_size as usize;
        if int_sz == 0 || int_sz > 8 {
            return None;
        }
        let n = usize::try_from(trailer.num_objects).ok()?;
        let table_off = usize::try_from(trailer.offset_table_offset).ok()?;
        let table_bytes = n.checked_mul(int_sz)?;
        if table_off.checked_add(table_bytes)? > data.len() {
            return None;
        }

        let mut offsets = Vec::with_capacity(n);
        for i in 0..n {
            let base = table_off + i * int_sz;
            let mut val = 0usize;
            for j in 0..int_sz {
                val = (val << 8) | (data[base + j] as usize);
            }
            offsets.push(val);
        }
        Some(Self { offsets })
    }

    /// Get the byte offset for object `idx`.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<usize> {
        self.offsets.get(idx).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjectTable
// ─────────────────────────────────────────────────────────────────────────────

/// The decoded object table.
#[derive(Debug, Clone)]
pub struct ObjectTable {
    /// Decoded objects in index order.
    pub objects: Vec<BplistObject>,
}

// ─────────────────────────────────────────────────────────────────────────────
// BplistReader
// ─────────────────────────────────────────────────────────────────────────────

/// Reader for binary plist (`bplist00`) data.
pub struct BplistReader<'a> {
    data: &'a [u8],
    trailer: BplistTrailer,
    offsets: OffsetTable,
}

impl<'a> BplistReader<'a> {
    /// Validate magic and parse the structural metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BplistError`] when `data` is not a valid `bplist00` file.
    pub fn new(data: &'a [u8]) -> Result<Self, BplistError> {
        if data.len() < 40 {
            return Err(BplistError::TooShort(40, data.len()));
        }
        if &data[..8] != b"bplist00" {
            return Err(BplistError::InvalidMagic);
        }
        let trailer = BplistTrailer::parse(data)
            .ok_or_else(|| BplistError::TrailerError("could not parse trailer".into()))?;
        let offsets = OffsetTable::parse(data, &trailer)
            .ok_or_else(|| BplistError::TrailerError("could not parse offset table".into()))?;
        Ok(Self {
            data,
            trailer,
            offsets,
        })
    }

    /// Decode and return the top-level object.
    ///
    /// # Errors
    ///
    /// Returns [`BplistError`] on decoding failure.
    pub fn root_object(&self) -> Result<BplistObject, BplistError> {
        self.decode_object(usize::try_from(self.trailer.top_object).map_err(|_| BplistError::ObjectError("top_object overflow".into()))?, 0)
    }

    fn decode_real(data: &[u8], byte_off: usize, info: usize) -> Result<BplistObject, BplistError> {
        let byte_width = 1usize << info;
        let off = byte_off + 1;
        if off + byte_width > data.len() { return Err(BplistError::ObjectError("real truncated".into())); }
        let v = match byte_width {
            4 => { let b: [u8; 4] = data[off..off + 4].try_into().unwrap(); f64::from(f32::from_be_bytes(b)) }
            8 => { let b: [u8; 8] = data[off..off + 8].try_into().unwrap(); f64::from_be_bytes(b) }
            _ => 0.0,
        };
        Ok(BplistObject::Real(v))
    }

    fn decode_utf16(data: &[u8], byte_off: usize, char_count: usize, header_sz: usize) -> Result<BplistObject, BplistError> {
        let off = byte_off + 1 + header_sz;
        let byte_len = char_count.checked_mul(2).ok_or(BplistError::IntegerOverflow)?;
        if off + byte_len > data.len() { return Err(BplistError::ObjectError("UTF-16 string truncated".into())); }
        let u16s: Vec<u16> = data[off..off + byte_len].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        Ok(BplistObject::Utf16String(String::from_utf16_lossy(&u16s)))
    }

    fn decode_array(&self, data: &[u8], byte_off: usize, count: usize, header_sz: usize, depth: usize) -> Result<BplistObject, BplistError> {
        let ref_sz = self.trailer.object_ref_size as usize;
        let refs_off = byte_off + 1 + header_sz;
        if refs_off + count * ref_sz > data.len() { return Err(BplistError::ObjectError("array refs truncated".into())); }
        let mut items = Vec::with_capacity(count);
        for i in 0..count {
            let roff = refs_off + i * ref_sz;
            let ref_idx = usize::try_from(read_be_int(data, roff, ref_sz)?).map_err(|_| BplistError::ObjectError("ref_idx overflow".into()))?;
            items.push(self.decode_object(ref_idx, depth + 1)?);
        }
        Ok(BplistObject::Array(items))
    }

    fn decode_dict(&self, data: &[u8], byte_off: usize, count: usize, header_sz: usize, depth: usize) -> Result<BplistObject, BplistError> {
        let ref_sz = self.trailer.object_ref_size as usize;
        let refs_off = byte_off + 1 + header_sz;
        if refs_off + count * 2 * ref_sz > data.len() { return Err(BplistError::ObjectError("dict refs truncated".into())); }
        let mut pairs = Vec::with_capacity(count);
        for i in 0..count {
            let key_off = refs_off + i * ref_sz;
            let val_off = refs_off + (count + i) * ref_sz;
            let key_idx = usize::try_from(read_be_int(data, key_off, ref_sz)?).map_err(|_| BplistError::ObjectError("key_idx overflow".into()))?;
            let val_idx = usize::try_from(read_be_int(data, val_off, ref_sz)?).map_err(|_| BplistError::ObjectError("val_idx overflow".into()))?;
            pairs.push((self.decode_object(key_idx, depth + 1)?, self.decode_object(val_idx, depth + 1)?));
        }
        Ok(BplistObject::Dict(pairs))
    }

    /// Decode object at `obj_idx` in the offset table with recursion guard.
    fn decode_object(&self, obj_idx: usize, depth: usize) -> Result<BplistObject, BplistError> {
        if depth > 128 { return Err(BplistError::ObjectError("recursion limit exceeded".into())); }
        let num = usize::try_from(self.trailer.num_objects).map_err(|_| BplistError::IndexOutOfBounds(obj_idx, 0))?;
        if obj_idx >= num { return Err(BplistError::IndexOutOfBounds(obj_idx, num)); }
        let byte_off = self.offsets.get(obj_idx).ok_or(BplistError::IndexOutOfBounds(obj_idx, num))?;
        let data = self.data;
        if byte_off >= data.len() { return Err(BplistError::ObjectError(format!("offset {byte_off:#x} out of bounds"))); }
        let marker = data[byte_off];
        let tag = marker >> 4;
        let info = (marker & 0x0F) as usize;
        match tag {
            0x0 => match info {
                0x8 => Ok(BplistObject::Bool(false)),
                0x9 => Ok(BplistObject::Bool(true)),
                0x0 | 0xF => Ok(BplistObject::Null),
                _ => Err(BplistError::UnsupportedTag(marker)),
            },
            0x1 => {
                let byte_width = 1usize << info;
                let off = byte_off + 1;
                if off + byte_width > data.len() { return Err(BplistError::ObjectError("integer truncated".into())); }
                Ok(BplistObject::Int(read_be_int(data, off, byte_width)?))
            }
            0x2 => Self::decode_real(data, byte_off, info),
            0x3 => {
                if info != 0x3 { return Err(BplistError::UnsupportedTag(marker)); }
                let off = byte_off + 1;
                if off + 8 > data.len() { return Err(BplistError::ObjectError("date truncated".into())); }
                let b: [u8; 8] = data[off..off + 8].try_into().unwrap();
                Ok(BplistObject::Date(f64::from_be_bytes(b)))
            }
            0x4 => {
                let (len, header_sz) = self.decode_length(info, byte_off)?;
                let off = byte_off + 1 + header_sz;
                if off + len > data.len() { return Err(BplistError::ObjectError("data truncated".into())); }
                Ok(BplistObject::Data(data[off..off + len].to_vec()))
            }
            0x5 => {
                let (len, header_sz) = self.decode_length(info, byte_off)?;
                let off = byte_off + 1 + header_sz;
                if off + len > data.len() { return Err(BplistError::ObjectError("ASCII string truncated".into())); }
                let s = std::str::from_utf8(&data[off..off + len]).map_or_else(
                    |_| String::from_utf8_lossy(&data[off..off + len]).into_owned(),
                    std::string::ToString::to_string,
                );
                Ok(BplistObject::String(s))
            }
            0x6 => { let (char_count, header_sz) = self.decode_length(info, byte_off)?; Self::decode_utf16(data, byte_off, char_count, header_sz) }
            0x8 => {
                let byte_width = info + 1;
                let off = byte_off + 1;
                if off + byte_width > data.len() { return Err(BplistError::ObjectError("UID truncated".into())); }
                Ok(BplistObject::Uid(read_be_int(data, off, byte_width)?.cast_unsigned()))
            }
            0xA => { let (count, header_sz) = self.decode_length(info, byte_off)?; self.decode_array(data, byte_off, count, header_sz, depth) }
            0xD => { let (count, header_sz) = self.decode_length(info, byte_off)?; self.decode_dict(data, byte_off, count, header_sz, depth) }
            _ => Err(BplistError::UnsupportedTag(marker)),
        }
    }

    /// Decode the length/count from the `info` nibble.
    ///
    /// When `info == 0x0F`, the actual length is encoded in an integer object
    /// immediately following the marker byte.  Returns `(length, extra_header_bytes)`.
    fn decode_length(&self, info: usize, marker_off: usize) -> Result<(usize, usize), BplistError> {
        if info < 0x0F {
            return Ok((info, 0));
        }
        // Extended length: next byte is 0x1N where N is log2 of the int width.
        let data = self.data;
        let int_off = marker_off + 1;
        if int_off >= data.len() {
            return Err(BplistError::ObjectError("length int truncated".into()));
        }
        let int_tag = data[int_off];
        let exp = u32::from(int_tag & 0x0F);
        let int_width = 1usize << exp;
        let val_off = int_off + 1;
        if val_off + int_width > data.len() {
            return Err(BplistError::ObjectError(
                "length int value truncated".into(),
            ));
        }
        let len = usize::try_from(read_be_int(data, val_off, int_width)?).map_err(|_| BplistError::ObjectError("length overflow".into()))?;
        // extra_header_bytes: 1 (int tag) + int_width
        Ok((len, 1 + int_width))
    }

    /// Return a flat-JSON representation of the root object.
    ///
    /// # Errors
    /// Returns [`BplistError`] if the root object cannot be decoded.
    pub fn to_json(&self) -> Result<String, BplistError> {
        Ok(self.root_object()?.to_json())
    }

    /// Return the trailer parsed from the file.
    #[must_use]
    pub const fn trailer(&self) -> &BplistTrailer {
        &self.trailer
    }

    /// Return the offset table.
    #[must_use]
    pub const fn offset_table(&self) -> &OffsetTable {
        &self.offsets
    }
}

/// Read a big-endian unsigned integer of `width` bytes from `data[offset..]`.
fn read_be_int(data: &[u8], offset: usize, width: usize) -> Result<i64, BplistError> {
    if width == 0 || offset + width > data.len() {
        return Err(BplistError::ObjectError(format!(
            "read_be_int: out of bounds (offset={offset}, width={width}, len={})",
            data.len()
        )));
    }
    let mut n = 0i64;
    for i in 0..width {
        n = (n << 8) | i64::from(data[offset + i]);
    }
    Ok(n)
}

// ─────────────────────────────────────────────────────────────────────────────
// bplist_parse — convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a binary plist from `data` and return the root [`BplistObject`].
///
/// # Errors
///
/// Returns [`BplistError`] on any parse failure.
pub fn bplist_parse(data: &[u8]) -> Result<BplistObject, BplistError> {
    BplistReader::new(data)?.root_object()
}

/// Parse a binary plist and convert the root to a JSON string.
///
/// # Errors
///
/// Returns [`BplistError`] on any parse failure.
pub fn bplist_to_json(data: &[u8]) -> Result<String, BplistError> {
    BplistReader::new(data)?.to_json()
}

/// Returns `true` when `data` starts with the binary plist magic `bplist00`.
#[must_use]
pub fn is_binary_plist(data: &[u8]) -> bool {
    data.starts_with(b"bplist00")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Build a minimal `bplist00` file containing a single root object.
///
/// Layout:
/// ```text
/// [0..8]   magic "bplist00"
/// [8..]    object data
/// [N-32..N] trailer
/// ```
#[cfg(test)]
mod tests {
    use super::*;

    /// Build the minimal bplist00 binary for a single boolean.
    fn make_bool_plist(value: bool) -> Vec<u8> {
        // Object byte: 0x08 = false, 0x09 = true (tag 0x0, info 8/9)
        let obj_byte: u8 = if value { 0x09 } else { 0x08 };
        make_single_object_plist(obj_byte, &[])
    }

    fn make_int_plist(n: u8) -> Vec<u8> {
        // Tag 0x1 (int), info 0 (1 byte)
        make_single_object_plist(0x10, &[n])
    }

    fn make_ascii_string_plist(s: &str) -> Vec<u8> {
        // Tag 0x5 (ASCII), info = len (if < 15)
        assert!(s.len() < 15, "use extended length for longer strings");
        let marker = 0x50_u8 | (s.len() as u8);
        let mut extra = Vec::new();
        extra.extend_from_slice(s.as_bytes());
        make_single_object_plist(marker, &extra)
    }

    /// Build a minimal single-object bplist00.
    fn make_single_object_plist(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // Magic
        data.extend_from_slice(b"bplist00");
        // Object: marker + payload
        let obj_off = data.len();
        data.push(marker);
        data.extend_from_slice(payload);
        // Offset table (1 entry, 1 byte each)
        let offset_table_off = data.len();
        data.push(obj_off as u8);
        // Trailer (32 bytes)
        let mut trailer = [0u8; 32];
        trailer[6] = 1; // offset_int_size
        trailer[7] = 1; // object_ref_size
        // num_objects = 1 (big-endian u64 at bytes 8-15)
        trailer[15] = 1;
        // top_object = 0 (already 0)
        // offset_table_offset (bytes 24-31)
        trailer[31] = offset_table_off as u8;
        data.extend_from_slice(&trailer);
        data
    }

    // ── is_binary_plist ───────────────────────────────────────────────────────

    #[test]
    fn test_is_binary_plist_true() {
        let p = make_bool_plist(true);
        assert!(is_binary_plist(&p));
    }

    #[test]
    fn test_is_binary_plist_false_for_xml() {
        assert!(!is_binary_plist(b"<?xml version"));
    }

    #[test]
    fn test_is_binary_plist_false_for_empty() {
        assert!(!is_binary_plist(&[]));
    }

    // ── BplistError display ───────────────────────────────────────────────────

    #[test]
    fn test_error_too_short_display() {
        let e = BplistError::TooShort(40, 10);
        assert!(e.to_string().contains("40"));
    }

    #[test]
    fn test_error_invalid_magic_display() {
        let e = BplistError::InvalidMagic;
        assert!(e.to_string().contains("magic"));
    }

    // ── BplistReader ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_too_short() {
        assert!(matches!(
            BplistReader::new(&[0u8; 10]),
            Err(BplistError::TooShort(..))
        ));
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = [0u8; 40];
        assert!(matches!(
            BplistReader::new(&data),
            Err(BplistError::InvalidMagic)
        ));
    }

    #[test]
    fn test_parse_bool_true() {
        let data = make_bool_plist(true);
        let obj = bplist_parse(&data).unwrap();
        assert_eq!(obj.as_bool(), Some(true));
    }

    #[test]
    fn test_parse_bool_false() {
        let data = make_bool_plist(false);
        let obj = bplist_parse(&data).unwrap();
        assert_eq!(obj.as_bool(), Some(false));
    }

    #[test]
    fn test_parse_int() {
        let data = make_int_plist(42);
        let obj = bplist_parse(&data).unwrap();
        assert_eq!(obj.as_i64(), Some(42));
    }

    #[test]
    fn test_parse_ascii_string() {
        let data = make_ascii_string_plist("hello");
        let obj = bplist_parse(&data).unwrap();
        assert_eq!(obj.as_str(), Some("hello"));
    }

    #[test]
    fn test_parse_empty_string() {
        let data = make_ascii_string_plist("");
        let obj = bplist_parse(&data).unwrap();
        assert_eq!(obj.as_str(), Some(""));
    }

    // ── BplistObject ──────────────────────────────────────────────────────────

    #[test]
    fn test_bool_true_json() {
        assert_eq!(BplistObject::Bool(true).to_json(), "true");
    }

    #[test]
    fn test_bool_false_json() {
        assert_eq!(BplistObject::Bool(false).to_json(), "false");
    }

    #[test]
    fn test_int_json() {
        assert_eq!(BplistObject::Int(100).to_json(), "100");
    }

    #[test]
    fn test_string_json() {
        let obj = BplistObject::String("hello \"world\"".into());
        let j = obj.to_json();
        assert!(j.contains("hello"));
        assert!(j.starts_with('"'));
    }

    #[test]
    fn test_null_json() {
        assert_eq!(BplistObject::Null.to_json(), "null");
    }

    #[test]
    fn test_uid_json() {
        let obj = BplistObject::Uid(5);
        assert!(obj.to_json().contains('5'));
    }

    #[test]
    fn test_array_json() {
        let obj = BplistObject::Array(vec![BplistObject::Int(1), BplistObject::Int(2)]);
        let j = obj.to_json();
        assert!(j.starts_with('['));
        assert!(j.ends_with(']'));
        assert!(j.contains('1'));
        assert!(j.contains('2'));
    }

    #[test]
    fn test_dict_json() {
        let obj = BplistObject::Dict(vec![(
            BplistObject::String("key".into()),
            BplistObject::Int(99),
        )]);
        let j = obj.to_json();
        assert!(j.contains("key"));
        assert!(j.contains("99"));
    }

    #[test]
    fn test_data_json() {
        let obj = BplistObject::Data(vec![0u8; 10]);
        assert!(obj.to_json().contains("10 bytes"));
    }

    #[test]
    fn test_date_json() {
        let obj = BplistObject::Date(0.0);
        assert!(obj.to_json().contains("date"));
    }

    // ── BplistObject accessors ────────────────────────────────────────────────

    #[test]
    fn test_as_str_string() {
        let obj = BplistObject::String("test".into());
        assert_eq!(obj.as_str(), Some("test"));
    }

    #[test]
    fn test_as_str_utf16() {
        let obj = BplistObject::Utf16String("hello".into());
        assert_eq!(obj.as_str(), Some("hello"));
    }

    #[test]
    fn test_as_str_non_string() {
        assert_eq!(BplistObject::Int(1).as_str(), None);
    }

    #[test]
    fn test_as_i64() {
        assert_eq!(BplistObject::Int(-5).as_i64(), Some(-5));
        assert_eq!(BplistObject::Bool(true).as_i64(), None);
    }

    #[test]
    fn test_as_array() {
        let a = BplistObject::Array(vec![BplistObject::Null]);
        assert_eq!(a.as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_as_dict() {
        let d = BplistObject::Dict(vec![(BplistObject::String("k".into()), BplistObject::Null)]);
        assert_eq!(d.as_dict().unwrap().len(), 1);
    }

    // ── Trailer ───────────────────────────────────────────────────────────────

    #[test]
    fn test_trailer_parse_too_short() {
        assert!(BplistTrailer::parse(&[0u8; 20]).is_none());
    }

    #[test]
    fn test_trailer_parse_valid() {
        let data = make_bool_plist(true);
        let t = BplistTrailer::parse(&data).unwrap();
        assert_eq!(t.offset_int_size, 1);
        assert_eq!(t.num_objects, 1);
        assert_eq!(t.top_object, 0);
    }

    // ── OffsetTable ───────────────────────────────────────────────────────────

    #[test]
    fn test_offset_table_get() {
        let t = OffsetTable {
            offsets: vec![8, 16, 24],
        };
        assert_eq!(t.get(0), Some(8));
        assert_eq!(t.get(2), Some(24));
        assert_eq!(t.get(3), None);
    }

    // ── bplist_to_json ────────────────────────────────────────────────────────

    #[test]
    fn test_bplist_to_json_bool() {
        let data = make_bool_plist(true);
        let json = bplist_to_json(&data).unwrap();
        assert_eq!(json, "true");
    }

    #[test]
    fn test_bplist_to_json_error_on_bad_data() {
        assert!(bplist_to_json(&[0u8; 10]).is_err());
    }
}
