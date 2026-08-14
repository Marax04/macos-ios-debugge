//! WebAssembly type decoder.
//!
//! Provides deep decoding of the Wasm *type section* and auxiliary type
//! encodings: value types, function types, table types, memory types, global
//! types, reference types, and block types.
//!
//! The main entry point is [`WasmTypeDecoder`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Leb128Decoder, WasmError, WasmFuncType, WasmValType};

// ---------------------------------------------------------------------------
// Extended value types (MVP + proposals)
// ---------------------------------------------------------------------------

/// A WebAssembly reference type (`funcref`, `externref`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmRefType {
    /// `funcref` (0x70) — reference to a function.
    FuncRef,
    /// `externref` (0x6F) — reference to an external object.
    ExternRef,
}

impl WasmRefType {
    /// Parse from a byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x70 => Some(Self::FuncRef),
            0x6F => Some(Self::ExternRef),
            _ => None,
        }
    }

    /// Encode to a byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::FuncRef => 0x70,
            Self::ExternRef => 0x6F,
        }
    }

    /// Text-format name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FuncRef => "funcref",
            Self::ExternRef => "externref",
        }
    }
}

impl fmt::Display for WasmRefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// WasmMemType
// ---------------------------------------------------------------------------

/// The type of a WebAssembly linear memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMemType {
    /// Minimum number of 64-KiB pages.
    pub min: u32,
    /// Optional maximum number of pages.
    pub max: Option<u32>,
    /// Whether this is a 64-bit (memory64 proposal) memory.
    pub is_64: bool,
    /// Whether the memory is shared (threads proposal).
    pub shared: bool,
}

impl WasmMemType {
    /// Default MVP 32-bit non-shared memory with given limits.
    #[must_use]
    pub const fn new(min: u32, max: Option<u32>) -> Self {
        Self {
            min,
            max,
            is_64: false,
            shared: false,
        }
    }

    /// Maximum addressable bytes given the current limits.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        let pages = u64::from(self.max.unwrap_or(if self.is_64 {
            u32::MAX
        } else {
            65536
        }));
        pages * 65536
    }
}

impl fmt::Display for WasmMemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bit_suffix = if self.is_64 { "i64" } else { "i32" };
        let shared = if self.shared { " shared" } else { "" };
        match self.max {
            Some(max) => write!(f, "memory {bit_suffix} {}{max}", self.min),
            None => write!(f, "memory {bit_suffix} {}{shared}", self.min),
        }
    }
}

// ---------------------------------------------------------------------------
// WasmTableType (richer version than the lib.rs struct)
// ---------------------------------------------------------------------------

/// A full table type descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmTableType {
    /// The reference type stored in the table.
    pub elem: WasmRefType,
    /// Minimum number of elements.
    pub min: u32,
    /// Optional maximum number of elements.
    pub max: Option<u32>,
}

impl WasmTableType {
    /// A `funcref` table with the given limits.
    #[must_use]
    pub const fn funcref(min: u32, max: Option<u32>) -> Self {
        Self {
            elem: WasmRefType::FuncRef,
            min,
            max,
        }
    }

    /// An `externref` table with the given limits.
    #[must_use]
    pub const fn externref(min: u32, max: Option<u32>) -> Self {
        Self {
            elem: WasmRefType::ExternRef,
            min,
            max,
        }
    }
}

impl fmt::Display for WasmTableType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.max {
            Some(max) => write!(f, "table {} {} {}", self.min, max, self.elem),
            None => write!(f, "table {} {}", self.min, self.elem),
        }
    }
}

// ---------------------------------------------------------------------------
// WasmGlobalType (self-contained, not re-using lib.rs)
// ---------------------------------------------------------------------------

/// A global variable type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmGlobalTypeFull {
    /// The value type of the global.
    pub val_type: WasmValType,
    /// Whether the global can be mutated.
    pub mutable: bool,
}

impl WasmGlobalTypeFull {
    /// Create an immutable global.
    #[must_use]
    pub const fn immutable(val_type: WasmValType) -> Self {
        Self { val_type, mutable: false }
    }

    /// Create a mutable global.
    #[must_use]
    pub const fn mutable(val_type: WasmValType) -> Self {
        Self { val_type, mutable: true }
    }
}

impl fmt::Display for WasmGlobalTypeFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mutable {
            write!(f, "(mut {})", self.val_type)
        } else {
            write!(f, "{}", self.val_type)
        }
    }
}

// ---------------------------------------------------------------------------
// BlockType
// ---------------------------------------------------------------------------

/// A block type used by `block`, `loop`, and `if` instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmBlockType {
    /// Empty block: no parameters and no results.
    Empty,
    /// Single value result type.
    Value(WasmValType),
    /// Function-type index (multi-value proposal).
    FuncTypeIndex(u32),
}

impl WasmBlockType {
    /// Parse from a signed LEB128 immediate.
    ///
    /// The Wasm spec encodes block types as an `i33` signed value:
    /// - `-0x40` (i.e. 0x40 encoded as SLEB = -64) → empty type.
    /// - Negative values matching value-type bytes → single-value type.
    /// - Non-negative values → type index.
    #[must_use]
    pub fn from_sleb128(v: i32) -> Option<Self> {
        match v {
            -0x40 => Some(Self::Empty),
            n if n < 0 => {
                let byte = (n & 0x7F) as u8;
                WasmValType::from_byte(byte).map(Self::Value)
            }
            n => Some(Self::FuncTypeIndex(n as u32)),
        }
    }
}

impl fmt::Display for WasmBlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "()"),
            Self::Value(v) => write!(f, "({v})"),
            Self::FuncTypeIndex(i) => write!(f, "(type {i})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TypeSection
// ---------------------------------------------------------------------------

/// The fully decoded Wasm type section.
#[derive(Debug, Clone, Default)]
pub struct TypeSection {
    /// All function type signatures in order.
    pub func_types: Vec<WasmFuncType>,
}

impl TypeSection {
    /// Look up a type by index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&WasmFuncType> {
        self.func_types.get(index as usize)
    }

    /// Number of types in this section.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.func_types.len()
    }

    /// Return `true` if the section contains no types.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.func_types.is_empty()
    }

    /// Return all types that match the given parameter/result signature.
    #[must_use]
    pub fn find_matching(
        &self,
        params: &[WasmValType],
        results: &[WasmValType],
    ) -> Vec<u32> {
        self.func_types
            .iter()
            .enumerate()
            .filter(|(_, ft)| ft.params == params && ft.results == results)
            .map(|(i, _)| i as u32)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// WasmTypeDecoder
// ---------------------------------------------------------------------------

/// Deep decoder for the WebAssembly type section and auxiliary type encodings.
pub struct WasmTypeDecoder;

impl WasmTypeDecoder {
    /// Decode a complete type section payload.
    ///
    /// The payload should be the raw bytes of the type section (after the
    /// section id and length LEB128), as returned by `WasmSectionParser`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if the data is malformed.
    pub fn decode_type_section(payload: &[u8]) -> Result<TypeSection, WasmError> {
        let mut dec = Leb128Decoder::new(payload);
        let count = dec.read_u32()?;
        let mut func_types = Vec::with_capacity((count as usize).min(dec.remaining()));
        for _ in 0..count {
            func_types.push(Self::read_func_type(&mut dec)?);
        }
        Ok(TypeSection { func_types })
    }

    /// Decode a single `functype` from a decoder.
    ///
    /// Format: `0x60 vec(valtype) vec(valtype)`
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn read_func_type(dec: &mut Leb128Decoder<'_>) -> Result<WasmFuncType, WasmError> {
        let tag = dec.read_u8()?;
        if tag != 0x60 {
            return Err(WasmError::InvalidSection(tag));
        }
        let params = Self::read_valtype_vec(dec)?;
        let results = Self::read_valtype_vec(dec)?;
        Ok(WasmFuncType { params, results })
    }

    /// Decode a `vec(valtype)`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn read_valtype_vec(dec: &mut Leb128Decoder<'_>) -> Result<Vec<WasmValType>, WasmError> {
        let count = dec.read_u32()?;
        let mut types = Vec::with_capacity((count as usize).min(dec.remaining()));
        for _ in 0..count {
            let b = dec.read_u8()?;
            let vt = WasmValType::from_byte(b).ok_or(WasmError::InvalidSection(b))?;
            types.push(vt);
        }
        Ok(types)
    }

    /// Decode a single `valtype`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if the byte is not a valid value-type encoding.
    pub fn read_valtype(dec: &mut Leb128Decoder<'_>) -> Result<WasmValType, WasmError> {
        let b = dec.read_u8()?;
        WasmValType::from_byte(b).ok_or(WasmError::InvalidSection(b))
    }

    /// Decode a limits struct `{flag, min, [max]}`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn read_limits(dec: &mut Leb128Decoder<'_>) -> Result<(u32, Option<u32>), WasmError> {
        let flag = dec.read_u8()?;
        let min = dec.read_u32()?;
        let max = if flag & 0x01 != 0 {
            Some(dec.read_u32()?)
        } else {
            None
        };
        Ok((min, max))
    }

    /// Decode a `tabletype`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn read_table_type(dec: &mut Leb128Decoder<'_>) -> Result<WasmTableType, WasmError> {
        let et_byte = dec.read_u8()?;
        let elem = WasmRefType::from_byte(et_byte)
            .ok_or(WasmError::InvalidSection(et_byte))?;
        let (min, max) = Self::read_limits(dec)?;
        Ok(WasmTableType { elem, min, max })
    }

    /// Decode a `memtype` (limits only, since memories have only limits in MVP).
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn read_mem_type(dec: &mut Leb128Decoder<'_>) -> Result<WasmMemType, WasmError> {
        let flag = dec.read_u8()?;
        let is_64 = flag & 0x04 != 0;
        let shared = flag & 0x02 != 0;
        let min = dec.read_u32()?;
        let max = if flag & 0x01 != 0 {
            Some(dec.read_u32()?)
        } else {
            None
        };
        Ok(WasmMemType { min, max, is_64, shared })
    }

    /// Decode a `globaltype`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data, including a `mut` flag that is
    /// neither `0x00` (const) nor `0x01` (var) as required by the core spec.
    pub fn read_global_type(dec: &mut Leb128Decoder<'_>) -> Result<WasmGlobalTypeFull, WasmError> {
        let b = dec.read_u8()?;
        let val_type = WasmValType::from_byte(b).ok_or(WasmError::InvalidSection(b))?;
        let mutability = dec.read_u8()?;
        let mutable = match mutability {
            0x00 => false,
            0x01 => true,
            other => return Err(WasmError::InvalidSection(other)),
        };
        Ok(WasmGlobalTypeFull {
            val_type,
            mutable,
        })
    }

    /// Decode a block type from a signed LEB128 immediate.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if the encoding is not a valid block type.
    pub fn read_block_type(dec: &mut Leb128Decoder<'_>) -> Result<WasmBlockType, WasmError> {
        let v = dec.read_i32()?;
        WasmBlockType::from_sleb128(v).ok_or(WasmError::InvalidSection(0))
    }

    /// Encode a `WasmFuncType` back to bytes.
    #[must_use]
    pub fn encode_func_type(ft: &WasmFuncType) -> Vec<u8> {
        let mut out = vec![0x60u8];
        write_leb128_u32(&mut out, ft.params.len() as u32);
        for &vt in &ft.params {
            out.push(vt.to_byte());
        }
        write_leb128_u32(&mut out, ft.results.len() as u32);
        for &vt in &ft.results {
            out.push(vt.to_byte());
        }
        out
    }

    /// Encode a complete type section from a slice of `WasmFuncType`.
    #[must_use]
    pub fn encode_type_section(types: &[WasmFuncType]) -> Vec<u8> {
        let mut payload: Vec<u8> = Vec::new();
        write_leb128_u32(&mut payload, types.len() as u32);
        for ft in types {
            payload.extend_from_slice(&Self::encode_func_type(ft));
        }
        // Wrap with section id + length.
        let mut out = vec![0x01u8]; // section id = 1
        write_leb128_u32(&mut out, payload.len() as u32);
        out.extend_from_slice(&payload);
        out
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a u32 as unsigned LEB128 and append to `out`.
fn write_leb128_u32(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

// Extension trait for WasmValType to provide to_byte.
trait ValTypeByte {
    fn to_byte(self) -> u8;
}

impl ValTypeByte for WasmValType {
    fn to_byte(self) -> u8 {
        match self {
            Self::I32 => 0x7F,
            Self::I64 => 0x7E,
            Self::F32 => 0x7D,
            Self::F64 => 0x7C,
            Self::V128 => 0x7B,
            Self::FuncRef => 0x70,
            Self::ExternRef => 0x6F,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_func_type_raw(params: &[u8], results: &[u8]) -> Vec<u8> {
        let mut v = vec![0x60u8];
        v.push(params.len() as u8);
        v.extend_from_slice(params);
        v.push(results.len() as u8);
        v.extend_from_slice(results);
        v
    }

    fn type_section_payload(types: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![types.len() as u8];
        for t in types {
            v.extend_from_slice(t);
        }
        v
    }

    #[test]
    fn test_decode_empty_type_section() {
        let payload = vec![0x00u8]; // count = 0
        let ts = WasmTypeDecoder::decode_type_section(&payload).unwrap();
        assert!(ts.is_empty());
    }

    #[test]
    fn test_decode_single_func_type() {
        let ft = encode_func_type_raw(&[0x7F, 0x7E], &[0x7F]); // (i32, i64) -> i32
        let payload = type_section_payload(&[ft]);
        let ts = WasmTypeDecoder::decode_type_section(&payload).unwrap();
        assert_eq!(ts.len(), 1);
        let f = &ts.func_types[0];
        assert_eq!(f.params, vec![WasmValType::I32, WasmValType::I64]);
        assert_eq!(f.results, vec![WasmValType::I32]);
    }

    #[test]
    fn test_decode_void_func_type() {
        let ft = encode_func_type_raw(&[], &[]);
        let payload = type_section_payload(&[ft]);
        let ts = WasmTypeDecoder::decode_type_section(&payload).unwrap();
        assert_eq!(ts.len(), 1);
        assert!(ts.func_types[0].params.is_empty());
        assert!(ts.func_types[0].results.is_empty());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = vec![
            WasmFuncType { params: vec![WasmValType::I32], results: vec![WasmValType::I64] },
            WasmFuncType { params: vec![], results: vec![] },
        ];
        let section_bytes = WasmTypeDecoder::encode_type_section(&original);
        // Strip the section header (id + length LEB128) to get the payload.
        let payload_start = 1 + leb_len(section_bytes.len() as u32);
        let payload = &section_bytes[payload_start..];
        let ts = WasmTypeDecoder::decode_type_section(payload).unwrap();
        assert_eq!(ts.len(), 2);
        assert_eq!(ts.func_types[0].params, original[0].params);
        assert_eq!(ts.func_types[0].results, original[0].results);
    }

    fn leb_len(mut v: u32) -> usize {
        let mut n = 1;
        v >>= 7;
        while v > 0 { n += 1; v >>= 7; }
        n
    }

    #[test]
    fn test_read_table_type() {
        let data = vec![0x70u8, 0x00, 0x05]; // funcref, no max, min=5
        let mut dec = Leb128Decoder::new(&data);
        let tt = WasmTypeDecoder::read_table_type(&mut dec).unwrap();
        assert_eq!(tt.elem, WasmRefType::FuncRef);
        assert_eq!(tt.min, 5);
        assert_eq!(tt.max, None);
    }

    #[test]
    fn test_read_mem_type_no_max() {
        let data = vec![0x00u8, 0x01]; // flag=0, min=1
        let mut dec = Leb128Decoder::new(&data);
        let mt = WasmTypeDecoder::read_mem_type(&mut dec).unwrap();
        assert_eq!(mt.min, 1);
        assert_eq!(mt.max, None);
        assert!(!mt.is_64);
    }

    #[test]
    fn test_read_mem_type_with_max() {
        let data = vec![0x01u8, 0x01, 0x10]; // flag=1, min=1, max=16
        let mut dec = Leb128Decoder::new(&data);
        let mt = WasmTypeDecoder::read_mem_type(&mut dec).unwrap();
        assert_eq!(mt.min, 1);
        assert_eq!(mt.max, Some(16));
    }

    #[test]
    fn test_read_global_type_immutable() {
        let data = vec![0x7Fu8, 0x00]; // i32, immutable
        let mut dec = Leb128Decoder::new(&data);
        let gt = WasmTypeDecoder::read_global_type(&mut dec).unwrap();
        assert_eq!(gt.val_type, WasmValType::I32);
        assert!(!gt.mutable);
    }

    #[test]
    fn test_read_global_type_mutable() {
        let data = vec![0x7Eu8, 0x01]; // i64, mutable
        let mut dec = Leb128Decoder::new(&data);
        let gt = WasmTypeDecoder::read_global_type(&mut dec).unwrap();
        assert_eq!(gt.val_type, WasmValType::I64);
        assert!(gt.mutable);
    }

    #[test]
    fn test_block_type_empty() {
        // SLEB128 encoding of -64 = 0x40
        let data = vec![0x40u8];
        let mut dec = Leb128Decoder::new(&data);
        let bt = WasmTypeDecoder::read_block_type(&mut dec).unwrap();
        assert_eq!(bt, WasmBlockType::Empty);
    }

    #[test]
    fn test_block_type_value() {
        // SLEB128 of -1 encodes to 0x7F (i32 value type byte)
        let data = vec![0x7Fu8];
        let mut dec = Leb128Decoder::new(&data);
        let bt = WasmTypeDecoder::read_block_type(&mut dec).unwrap();
        assert_eq!(bt, WasmBlockType::Value(WasmValType::I32));
    }

    #[test]
    fn test_type_section_find_matching() {
        let ts = TypeSection {
            func_types: vec![
                WasmFuncType { params: vec![WasmValType::I32], results: vec![WasmValType::I32] },
                WasmFuncType { params: vec![], results: vec![] },
                WasmFuncType { params: vec![WasmValType::I32], results: vec![WasmValType::I32] },
            ],
        };
        let matches = ts.find_matching(&[WasmValType::I32], &[WasmValType::I32]);
        assert_eq!(matches, vec![0, 2]);
    }

    #[test]
    fn test_ref_type_roundtrip() {
        assert_eq!(WasmRefType::from_byte(0x70), Some(WasmRefType::FuncRef));
        assert_eq!(WasmRefType::from_byte(0x6F), Some(WasmRefType::ExternRef));
        assert_eq!(WasmRefType::from_byte(0x00), None);
    }

    #[test]
    fn test_mem_type_max_bytes() {
        let mt = WasmMemType::new(1, Some(10));
        assert_eq!(mt.max_bytes(), 10 * 65536);
    }

    #[test]
    fn test_global_type_display_immutable() {
        let gt = WasmGlobalTypeFull::immutable(WasmValType::I32);
        assert_eq!(gt.to_string(), "i32");
    }

    #[test]
    fn test_global_type_display_mutable() {
        let gt = WasmGlobalTypeFull::mutable(WasmValType::F64);
        assert_eq!(gt.to_string(), "(mut f64)");
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_read_table_type_unknown_ref_byte() {
        // 0xAB is not a valid wasm ref byte → expect error.
        let data = vec![0xABu8, 0x00, 0x05];
        let mut dec = Leb128Decoder::new(&data);
        assert!(WasmTypeDecoder::read_table_type(&mut dec).is_err());
    }

    #[test]
    fn test_read_mem_type_unknown_flag() {
        // Memory limits flag must be 0 or 1 (or 4/5 for memory64).
        let data = vec![0x09u8, 0x01];
        let mut dec = Leb128Decoder::new(&data);
        assert!(WasmTypeDecoder::read_mem_type(&mut dec).is_err());
    }

    #[test]
    fn test_read_global_type_bad_mut_flag() {
        // mut byte must be 0 or 1.
        let data = vec![0x7Fu8, 0x02];
        let mut dec = Leb128Decoder::new(&data);
        assert!(WasmTypeDecoder::read_global_type(&mut dec).is_err());
    }

    #[test]
    fn test_decode_type_section_empty() {
        // A type section with count=0 should decode to an empty list.
        let payload = vec![0x00u8];
        let ts = WasmTypeDecoder::decode_type_section(&payload).unwrap();
        assert_eq!(ts.len(), 0);
        assert!(ts.func_types.is_empty());
    }

    #[test]
    fn test_decode_type_section_truncated() {
        // Count says 1 but no payload follows.
        let payload = vec![0x01u8];
        assert!(WasmTypeDecoder::decode_type_section(&payload).is_err());
    }

    #[test]
    fn test_type_section_find_matching_no_match() {
        let ts = TypeSection {
            func_types: vec![
                WasmFuncType { params: vec![], results: vec![] },
            ],
        };
        let matches = ts.find_matching(&[WasmValType::I32], &[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_mem_type_max_bytes_zero_pages() {
        let mt = WasmMemType::new(0, Some(0));
        assert_eq!(mt.max_bytes(), 0);
    }

    #[test]
    fn test_block_type_empty_via_short_input_errors() {
        // Empty input → decoder cannot read block type.
        let data: Vec<u8> = vec![];
        let mut dec = Leb128Decoder::new(&data);
        assert!(WasmTypeDecoder::read_block_type(&mut dec).is_err());
    }
}
