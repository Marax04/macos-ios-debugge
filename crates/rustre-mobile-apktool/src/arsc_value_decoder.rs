//! `arsc_value_decoder` — Decode Android resource values from `resources.arsc`.
//!
//! The `Res_value` structure in `resources.arsc` carries a typed data word.
//! This module decodes it into human-readable representations and typed Rust
//! values for all standard Android data types.
//!
//! Reference: AOSP `libs/androidfw/include/androidfw/ResourceTypes.h`

use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// DataType
// ─────────────────────────────────────────────────────────────────────────────

/// The type byte of a `Res_value` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DataType {
    /// No type; usually means the value is a reference to another resource.
    Null = 0x00,
    /// Reference to another resource table entry.
    Reference = 0x01,
    /// Attribute resource identifier.
    Attribute = 0x02,
    /// Index into the string pool.
    String = 0x03,
    /// Single-precision floating-point.
    Float = 0x04,
    /// Complex floating-point: unit + mantissa packed into u32.
    Dimension = 0x05,
    /// Complex floating-point: fraction of screen size.
    Fraction = 0x06,
    /// Raw dynamic reference.
    DynamicReference = 0x07,
    /// First integer type.
    IntDec = 0x10,
    /// Unsigned integer in hexadecimal.
    IntHex = 0x11,
    /// Boolean.
    IntBoolean = 0x12,
    /// AARRGGBB colour.
    IntColorArgb8 = 0x1C,
    /// RRGGBB colour.
    IntColorRgb8 = 0x1D,
    /// AARRGGBB colour (4-bit components).
    IntColorArgb4 = 0x1E,
    /// RRGGBB colour (4-bit components).
    IntColorRgb4 = 0x1F,
    /// Unknown type.
    Unknown = 0xFF,
}

impl DataType {
    /// Decode a raw `u8` into a `DataType`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Null,
            0x01 => Self::Reference,
            0x02 => Self::Attribute,
            0x03 => Self::String,
            0x04 => Self::Float,
            0x05 => Self::Dimension,
            0x06 => Self::Fraction,
            0x07 => Self::DynamicReference,
            0x10 => Self::IntDec,
            0x11 => Self::IntHex,
            0x12 => Self::IntBoolean,
            0x1C => Self::IntColorArgb8,
            0x1D => Self::IntColorRgb8,
            0x1E => Self::IntColorArgb4,
            0x1F => Self::IntColorRgb4,
            _ => Self::Unknown,
        }
    }

    /// Return the canonical name of this data type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Reference => "reference",
            Self::Attribute => "attribute",
            Self::String => "string",
            Self::Float => "float",
            Self::Dimension => "dimension",
            Self::Fraction => "fraction",
            Self::DynamicReference => "dynamic_reference",
            Self::IntDec => "int_dec",
            Self::IntHex => "int_hex",
            Self::IntBoolean => "boolean",
            Self::IntColorArgb8 => "color_argb8",
            Self::IntColorRgb8 => "color_rgb8",
            Self::IntColorArgb4 => "color_argb4",
            Self::IntColorRgb4 => "color_rgb4",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this data type carries an integer value.
    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(self, Self::IntDec | Self::IntHex | Self::IntBoolean
            | Self::IntColorArgb8 | Self::IntColorRgb8
            | Self::IntColorArgb4 | Self::IntColorRgb4)
    }

    /// Returns `true` if this is a colour data type.
    #[must_use]
    pub const fn is_color(self) -> bool {
        matches!(self, Self::IntColorArgb8 | Self::IntColorRgb8
            | Self::IntColorArgb4 | Self::IntColorRgb4)
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dimension unit constants
// ─────────────────────────────────────────────────────────────────────────────

/// Unit suffix bits (lowest 4 bits of the mantissa unit byte).
pub const COMPLEX_UNIT_PX: u8 = 0;
pub const COMPLEX_UNIT_DIP: u8 = 1;
pub const COMPLEX_UNIT_SP: u8 = 2;
pub const COMPLEX_UNIT_PT: u8 = 3;
pub const COMPLEX_UNIT_IN: u8 = 4;
pub const COMPLEX_UNIT_MM: u8 = 5;

const fn complex_unit_suffix(unit: u8) -> &'static str {
    match unit & 0x0F {
        COMPLEX_UNIT_PX => "px",
        COMPLEX_UNIT_DIP => "dp",
        COMPLEX_UNIT_SP => "sp",
        COMPLEX_UNIT_PT => "pt",
        COMPLEX_UNIT_IN => "in",
        COMPLEX_UNIT_MM => "mm",
        _ => "?",
    }
}

#[inline]
const fn i32_to_f32_lossy(x: i32) -> f32 {
    // Deliberate boundary: complex resource mantissas exceed f32 precision but
    // the loss is acceptable for display purposes.
    x as f32
}

/// Decode a complex dimension or fraction mantissa to a float.
#[must_use]
pub fn decode_complex_mantissa(value: u32) -> f32 {
    const MANTISSA_MULT: f32 = 1.0 / 256.0;
    let mantissa = (value >> 8).cast_signed();
    let radix = (value >> 4) & 0x03;

    match radix {
        0 => i32_to_f32_lossy(mantissa),
        1 => i32_to_f32_lossy(mantissa) * (1.0 / 128.0),
        2 => i32_to_f32_lossy(mantissa) * (1.0 / 32_768.0),
        3 => i32_to_f32_lossy(mantissa) * (1.0 / 8_388_608.0),
        _ => i32_to_f32_lossy(mantissa) * MANTISSA_MULT,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResValue
// ─────────────────────────────────────────────────────────────────────────────

/// A typed, decoded Android resource value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResValue {
    /// The raw data type byte.
    pub data_type: DataType,
    /// The raw 32-bit data word.
    pub raw: u32,
    /// Human-readable string representation.
    pub display: String,
}

impl ResValue {
    /// Create a new `ResValue`.
    #[must_use]
    pub fn new(data_type: DataType, raw: u32, display: impl Into<String>) -> Self {
        Self { data_type, raw, display: display.into() }
    }

    /// Returns the resolved string value for `String` type, or `None`.
    #[must_use]
    pub fn as_string_index(&self) -> Option<usize> {
        if self.data_type == DataType::String {
            Some(self.raw as usize)
        } else {
            None
        }
    }

    /// Returns the boolean value for `IntBoolean` type, or `None`.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        if self.data_type == DataType::IntBoolean {
            Some(self.raw != 0)
        } else {
            None
        }
    }

    /// Returns the integer value for integer types, or `None`.
    #[must_use]
    pub const fn as_int(&self) -> Option<i32> {
        if self.data_type.is_integer() {
            Some(self.raw.cast_signed())
        } else {
            None
        }
    }

    /// Returns `true` if this value is a reference.
    #[must_use]
    pub fn is_reference(&self) -> bool {
        self.data_type == DataType::Reference
    }
}

impl fmt::Display for ResValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArscValueDecoder
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes raw `(data_type, data)` pairs from a `resources.arsc` entry into
/// typed [`ResValue`] representations.
///
/// # Usage
/// ```rust,ignore
/// let decoder = ArscValueDecoder::new(&string_pool);
/// let val = decoder.decode(0x03, 42); // TYPE_STRING, index 42
/// println!("{val}");
/// ```
#[derive(Debug, Clone, Default)]
pub struct ArscValueDecoder {
    /// String pool — used to resolve `TYPE_STRING` values.
    string_pool: Vec<String>,
}

impl ArscValueDecoder {
    /// Create a new decoder with a string pool.
    #[must_use]
    pub const fn new(string_pool: Vec<String>) -> Self {
        Self { string_pool }
    }

    /// Decode a `(data_type_byte, data)` pair into a [`ResValue`].
    #[must_use]
    pub fn decode(&self, data_type: u8, data: u32) -> ResValue {
        let dt = DataType::from_u8(data_type);
        let display = self.format_value(dt, data);
        ResValue::new(dt, data, display)
    }

    /// Decode a `Res_value` struct from raw bytes at `offset`.
    ///
    /// `Res_value` layout (8 bytes):
    /// `size(2) res0(1) dataType(1) data(4)`
    #[must_use]
    pub fn decode_bytes(&self, data: &[u8], offset: usize) -> Option<ResValue> {
        if offset + 8 > data.len() {
            return None;
        }
        let data_type = data[offset + 3];
        let raw = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
        Some(self.decode(data_type, raw))
    }

    // ── Format helpers ────────────────────────────────────────────────────────

    fn format_value(&self, dt: DataType, raw: u32) -> String {
        match dt {
            DataType::Null => String::from("@null"),
            DataType::Reference => format!("@{raw:#010x}"),
            DataType::Attribute => format!("?{raw:#010x}"),
            DataType::DynamicReference => format!("@dyn:{raw:#010x}"),
            DataType::String => self.format_string(raw),
            DataType::Float => {
                let f = f32::from_bits(raw);
                format!("{f}")
            }
            DataType::Dimension => Self::format_dimension(raw),
            DataType::Fraction => Self::format_fraction(raw),
            DataType::IntDec => format!("{}", raw.cast_signed()),
            DataType::IntHex => format!("{raw:#010x}"),
            DataType::IntBoolean => {
                if raw != 0 { "true".to_string() } else { "false".to_string() }
            }
            DataType::IntColorArgb8 => format!("#{raw:08X}"),
            DataType::IntColorRgb8 => format!("#{:06X}", raw & 0x00FF_FFFF),
            DataType::IntColorArgb4 => {
                let a = (raw >> 12) & 0xF;
                let r = (raw >> 8) & 0xF;
                let g = (raw >> 4) & 0xF;
                let b = raw & 0xF;
                format!("#{a:X}{r:X}{g:X}{b:X}")
            }
            DataType::IntColorRgb4 => {
                let r = (raw >> 8) & 0xF;
                let g = (raw >> 4) & 0xF;
                let b = raw & 0xF;
                format!("#{r:X}{g:X}{b:X}")
            }
            DataType::Unknown => format!("0x{raw:08x}"),
        }
    }

    fn format_string(&self, idx: u32) -> String {
        self.string_pool
            .get(idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("@string/{idx}"))
    }

    fn format_dimension(raw: u32) -> String {
        let mantissa = decode_complex_mantissa(raw);
        let unit = complex_unit_suffix(u8::try_from(raw & 0xff).unwrap_or(0));
        format!("{mantissa}{unit}")
    }

    fn format_fraction(raw: u32) -> String {
        let mantissa = decode_complex_mantissa(raw);
        let is_parent = (raw & 0x01) != 0;
        if is_parent {
            format!("{:.2}%p", mantissa * 100.0)
        } else {
            format!("{:.2}%", mantissa * 100.0)
        }
    }

    /// Decode a reference resource ID into its typed components.
    ///
    /// Android resource IDs are formatted as `0xPPTTEEEE`:
    /// - `PP` = package ID (e.g. 0x7F for app, 0x01 for framework)
    /// - `TT` = type ID
    /// - `EEEE` = entry ID
    #[must_use]
    pub const fn decode_resource_id(res_id: u32) -> ResourceId {
        let package = ((res_id >> 24) & 0xFF) as u8;
        let type_id = ((res_id >> 16) & 0xFF) as u8;
        let entry = (res_id & 0xFFFF) as u16;
        ResourceId { package, type_id, entry, raw: res_id }
    }

    /// Decode all entries from a flat list of `(data_type, data)` pairs.
    #[must_use]
    pub fn decode_all(&self, entries: &[(u8, u32)]) -> Vec<ResValue> {
        entries.iter().map(|&(dt, raw)| self.decode(dt, raw)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceId
// ─────────────────────────────────────────────────────────────────────────────

/// Decomposed Android resource ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceId {
    /// Package part (top 8 bits).
    pub package: u8,
    /// Type part (bits 16–23).
    pub type_id: u8,
    /// Entry part (lower 16 bits).
    pub entry: u16,
    /// Raw 32-bit ID.
    pub raw: u32,
}

impl ResourceId {
    /// Returns `true` if this is a framework resource (package = 0x01).
    #[must_use]
    pub const fn is_framework(&self) -> bool {
        self.package == 0x01
    }

    /// Returns `true` if this is an application resource (package = 0x7F).
    #[must_use]
    pub const fn is_app(&self) -> bool {
        self.package == 0x7F
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{:02X}{:02X}{:04X}", self.package, self.type_id, self.entry)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_attr_value() — standalone helper
// ─────────────────────────────────────────────────────────────────────────────

/// Decode an attribute value from an AXML attribute node.
///
/// AXML attribute layout (20 bytes):
/// ```text
/// ns_idx(4) name_idx(4) raw_val_idx(4) size(2) res0(1) dataType(1) data(4)
/// ```
///
/// Returns the `(data_type, data)` pair as a `ResValue`.
#[must_use]
pub fn decode_attr_value(
    attr_bytes: &[u8],
    offset: usize,
    string_pool: &[String],
) -> Option<ResValue> {
    if offset + 20 > attr_bytes.len() {
        return None;
    }
    let data_type = attr_bytes[offset + 15];
    let raw = u32::from_le_bytes([
        attr_bytes[offset + 16],
        attr_bytes[offset + 17],
        attr_bytes[offset + 18],
        attr_bytes[offset + 19],
    ]);
    let decoder = ArscValueDecoder::new(string_pool.to_vec());
    Some(decoder.decode(data_type, raw))
}

/// Decode a list of AXML attribute bytes (each 20 bytes) into `ResValues`.
#[must_use]
pub fn decode_attr_list(attr_bytes: &[u8], string_pool: &[String]) -> Vec<ResValue> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 20 <= attr_bytes.len() {
        if let Some(v) = decode_attr_value(attr_bytes, off, string_pool) {
            out.push(v);
        }
        off += 20;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// ColorComponents
// ─────────────────────────────────────────────────────────────────────────────

/// Extracted ARGB components from a colour resource value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorComponents {
    pub alpha: u8,
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl ColorComponents {
    /// Extract ARGB8888 components from a raw colour word.
    #[must_use]
    pub const fn from_argb8(raw: u32) -> Self {
        Self {
            alpha: ((raw >> 24) & 0xFF) as u8,
            red: ((raw >> 16) & 0xFF) as u8,
            green: ((raw >> 8) & 0xFF) as u8,
            blue: (raw & 0xFF) as u8,
        }
    }

    /// Reconstruct the 32-bit colour word.
    #[must_use]
    pub const fn to_argb8(self) -> u32 {
        (self.alpha as u32) << 24
            | (self.red as u32) << 16
            | (self.green as u32) << 8
            | self.blue as u32
    }

    /// Return `true` when the colour is fully opaque.
    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        self.alpha == 0xFF
    }

    /// Return a CSS-style `#RRGGBB` string.
    #[must_use]
    pub fn to_css_rgb(&self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.red, self.green, self.blue)
    }

    /// Return a CSS-style `rgba(r, g, b, a)` string.
    #[must_use]
    pub fn to_css_rgba(&self) -> String {
        let a = f32::from(self.alpha) / 255.0;
        format!("rgba({},{},{},{:.3})", self.red, self.green, self.blue, a)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn decoder() -> ArscValueDecoder {
        ArscValueDecoder::new(vec!["hello".to_string(), "world".to_string()])
    }

    #[test]
    fn test_decode_boolean_true() {
        let d = decoder();
        let v = d.decode(DataType::IntBoolean as u8, 1);
        assert_eq!(v.display, "true");
        assert_eq!(v.as_bool(), Some(true));
    }

    #[test]
    fn test_decode_boolean_false() {
        let d = decoder();
        let v = d.decode(DataType::IntBoolean as u8, 0);
        assert_eq!(v.display, "false");
        assert_eq!(v.as_bool(), Some(false));
    }

    #[test]
    fn test_decode_string_in_pool() {
        let d = decoder();
        let v = d.decode(DataType::String as u8, 0);
        assert_eq!(v.display, "hello");
        assert_eq!(v.as_string_index(), Some(0));
    }

    #[test]
    fn test_decode_string_out_of_pool() {
        let d = decoder();
        let v = d.decode(DataType::String as u8, 99);
        assert!(v.display.starts_with("@string/"));
    }

    #[test]
    fn test_decode_reference() {
        let d = decoder();
        let v = d.decode(DataType::Reference as u8, 0x7F04_0001);
        assert!(v.display.starts_with("@0x"));
        assert!(v.is_reference());
    }

    #[test]
    fn test_decode_hex_int() {
        let d = decoder();
        let v = d.decode(DataType::IntHex as u8, 0xDEAD_BEEF);
        assert_eq!(v.display, "0xdeadbeef");
    }

    #[test]
    fn test_decode_dec_int() {
        let d = decoder();
        let v = d.decode(DataType::IntDec as u8, 42);
        assert_eq!(v.display, "42");
    }

    #[test]
    fn test_decode_color_argb8() {
        let d = decoder();
        let v = d.decode(DataType::IntColorArgb8 as u8, 0xFF11_2233);
        assert_eq!(v.display, "#FF112233");
    }

    #[test]
    fn test_decode_null() {
        let d = decoder();
        let v = d.decode(DataType::Null as u8, 0);
        assert_eq!(v.display, "@null");
    }

    #[test]
    fn test_decode_resource_id() {
        let id = ArscValueDecoder::decode_resource_id(0x7F04_0001);
        assert_eq!(id.package, 0x7F);
        assert_eq!(id.type_id, 0x04);
        assert_eq!(id.entry, 0x0001);
        assert!(id.is_app());
        assert!(!id.is_framework());
    }

    #[test]
    fn test_decode_resource_id_framework() {
        let id = ArscValueDecoder::decode_resource_id(0x0102_0003);
        assert!(id.is_framework());
    }

    #[test]
    fn test_color_components_from_argb8() {
        let c = ColorComponents::from_argb8(0xFF_FF0000);
        assert_eq!(c.alpha, 0xFF);
        assert_eq!(c.red, 0xFF);
        assert_eq!(c.green, 0);
        assert_eq!(c.blue, 0);
        assert!(c.is_opaque());
    }

    #[test]
    fn test_color_css_rgb() {
        let c = ColorComponents { alpha: 0xFF, red: 0x12, green: 0x34, blue: 0x56 };
        assert_eq!(c.to_css_rgb(), "#123456");
    }

    #[test]
    fn test_color_roundtrip() {
        let raw = 0xAABB_CCDD_u32;
        let c = ColorComponents::from_argb8(raw);
        assert_eq!(c.to_argb8(), raw);
    }

    #[test]
    fn test_data_type_from_u8_unknown() {
        let dt = DataType::from_u8(0xFE);
        assert_eq!(dt, DataType::Unknown);
    }

    #[test]
    fn test_data_type_is_color() {
        assert!(DataType::IntColorArgb8.is_color());
        assert!(!DataType::IntDec.is_color());
    }

    #[test]
    fn test_decode_attr_value_too_short() {
        let bytes = vec![0u8; 10];
        let pool: Vec<String> = vec![];
        assert!(decode_attr_value(&bytes, 0, &pool).is_none());
    }

    #[test]
    fn test_decode_attr_list_empty() {
        let pool: Vec<String> = vec![];
        let list = decode_attr_list(&[], &pool);
        assert!(list.is_empty());
    }

    #[test]
    fn test_decode_all() {
        let d = decoder();
        let pairs = vec![(DataType::IntDec as u8, 10u32), (DataType::IntBoolean as u8, 1u32)];
        let vals = d.decode_all(&pairs);
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0].display, "10");
        assert_eq!(vals[1].display, "true");
    }
}
