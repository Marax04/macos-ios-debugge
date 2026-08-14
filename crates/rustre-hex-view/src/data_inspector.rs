//! `data_inspector` — Inspect bytes at a cursor position.
//!
//! Reads a window of bytes and interprets them as many different types
//! simultaneously: integers of various widths, floats, timestamps, GUIDs,
//! and printable strings.
//!
//! Key types: [`DataInspector`], [`InspectorResult`], [`DataInterpretation`],
//! [`inspect_at`]

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors returned by the inspector.
#[derive(Debug, thiserror::Error)]
pub enum InspectorError {
    #[error("offset {0} is out of range (data length {1})")]
    OutOfRange(usize, usize),
    #[error("insufficient bytes: need {needed}, have {have}")]
    InsufficientBytes { needed: usize, have: usize },
}

// ─── Endianness ───────────────────────────────────────────────────────────────

/// Byte order for multi-byte types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(f, "LE"),
            Self::Big => write!(f, "BE"),
        }
    }
}

// ─── DataInterpretation ───────────────────────────────────────────────────────

/// A single interpretation of the bytes at the cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataInterpretation {
    /// Unsigned 8-bit integer.
    U8(u8),
    /// Signed 8-bit integer.
    I8(i8),
    /// Unsigned 16-bit integer.
    U16 { value: u16, endian: Endian },
    /// Signed 16-bit integer.
    I16 { value: i16, endian: Endian },
    /// Unsigned 32-bit integer.
    U32 { value: u32, endian: Endian },
    /// Signed 32-bit integer.
    I32 { value: i32, endian: Endian },
    /// Unsigned 64-bit integer.
    U64 { value: u64, endian: Endian },
    /// Signed 64-bit integer.
    I64 { value: i64, endian: Endian },
    /// 32-bit IEEE 754 float.
    F32 { value: f32, endian: Endian },
    /// 64-bit IEEE 754 float.
    F64 { value: f64, endian: Endian },
    /// Unix timestamp (seconds since 1970-01-01) interpreted as a date string.
    UnixTimestamp { raw: u64, formatted: String },
    /// Windows FILETIME (100-ns intervals since 1601-01-01).
    FileTime { raw: u64, formatted: String },
    /// Windows GUID / UUID as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    Guid(String),
    /// Null-terminated ASCII/UTF-8 string (up to `max_len` bytes).
    CString(String),
    /// IPv4 address (4 bytes).
    Ipv4(String),
    /// IPv6 address (16 bytes).
    Ipv6(String),
    /// Bit field display (8 bits).
    Bits8(String),
    /// Bit field display (16 bits).
    Bits16 { value: String, endian: Endian },
}

impl DataInterpretation {
    /// Human-readable name for this interpretation.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::U8(_) => "uint8",
            Self::I8(_) => "int8",
            Self::U16 { .. } => "uint16",
            Self::I16 { .. } => "int16",
            Self::U32 { .. } => "uint32",
            Self::I32 { .. } => "int32",
            Self::U64 { .. } => "uint64",
            Self::I64 { .. } => "int64",
            Self::F32 { .. } => "float32",
            Self::F64 { .. } => "float64",
            Self::UnixTimestamp { .. } => "unix_timestamp",
            Self::FileTime { .. } => "windows_filetime",
            Self::Guid(_) => "guid",
            Self::CString(_) => "c_string",
            Self::Ipv4(_) => "ipv4",
            Self::Ipv6(_) => "ipv6",
            Self::Bits8(_) => "bits8",
            Self::Bits16 { .. } => "bits16",
        }
    }

    /// The formatted value as a string.
    #[must_use]
    pub fn value_str(&self) -> String {
        match self {
            Self::U8(v) => format!("{v}"),
            Self::I8(v) => format!("{v}"),
            Self::U16 { value, endian } => format!("{value} ({endian})"),
            Self::I16 { value, endian } => format!("{value} ({endian})"),
            Self::U32 { value, endian } => format!("{value} ({endian})"),
            Self::I32 { value, endian } => format!("{value} ({endian})"),
            Self::U64 { value, endian } => format!("{value} ({endian})"),
            Self::I64 { value, endian } => format!("{value} ({endian})"),
            Self::F32 { value, endian } => format!("{value} ({endian})"),
            Self::F64 { value, endian } => format!("{value} ({endian})"),
            Self::UnixTimestamp { raw, formatted } => format!("{raw} → {formatted}"),
            Self::FileTime { raw, formatted } => format!("{raw} → {formatted}"),
            Self::Guid(s) => s.clone(),
            Self::CString(s) => format!("\"{s}\""),
            Self::Ipv4(s) | Self::Ipv6(s) => s.clone(),
            Self::Bits8(s) | Self::Bits16 { value: s, .. } => s.clone(),
        }
    }
}

impl fmt::Display for DataInterpretation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<20} = {}", self.type_name(), self.value_str())
    }
}

// ─── InspectorResult ──────────────────────────────────────────────────────────

/// The collection of all interpretations for a cursor position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectorResult {
    /// File offset at which inspection was performed.
    pub offset: usize,
    /// All interpretations, in order.
    pub interpretations: Vec<DataInterpretation>,
    /// Raw bytes used (up to 16 bytes from offset).
    pub raw_bytes: Vec<u8>,
}

impl InspectorResult {
    /// Find an interpretation by type name.
    #[must_use]
    pub fn get(&self, type_name: &str) -> Option<&DataInterpretation> {
        self.interpretations
            .iter()
            .find(|i| i.type_name() == type_name)
    }

    /// Return all interpretations as a display string.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!("Offset: {:#x}\n", self.offset);
        for interp in &self.interpretations {
            s.push_str(&format!("  {interp}\n"));
        }
        s
    }
}

// ─── InspectorConfig ──────────────────────────────────────────────────────────

/// Options that control what interpretations are produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectorConfig {
    /// Include little-endian multi-byte interpretations.
    pub little_endian: bool,
    /// Include big-endian multi-byte interpretations.
    pub big_endian: bool,
    /// Include float interpretations.
    pub floats: bool,
    /// Include timestamp interpretations.
    pub timestamps: bool,
    /// Include GUID interpretation (needs 16 bytes).
    pub guid: bool,
    /// Include C-string interpretation.
    pub cstring: bool,
    /// Include IPv4/IPv6 interpretation.
    pub ip_addresses: bool,
    /// Include bit-field display.
    pub bit_fields: bool,
    /// Maximum length for C-string extraction.
    pub max_cstring_len: usize,
}

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            little_endian: true,
            big_endian: true,
            floats: true,
            timestamps: true,
            guid: true,
            cstring: true,
            ip_addresses: true,
            bit_fields: true,
            max_cstring_len: 256,
        }
    }
}

impl InspectorConfig {
    /// A minimal config: only little-endian integers.
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            little_endian: true,
            big_endian: false,
            floats: false,
            timestamps: false,
            guid: false,
            cstring: false,
            ip_addresses: false,
            bit_fields: false,
            max_cstring_len: 64,
        }
    }
}

// ─── DataInspector ────────────────────────────────────────────────────────────

/// Inspects bytes at a given offset and produces typed interpretations.
pub struct DataInspector {
    config: InspectorConfig,
}

impl DataInspector {
    /// Create an inspector with a custom configuration.
    #[must_use]
    pub const fn new(config: InspectorConfig) -> Self {
        Self { config }
    }

    /// Create an inspector with default (all) interpretations enabled.
    #[must_use]
    pub fn all() -> Self {
        Self::new(InspectorConfig::default())
    }

    /// Create an inspector with only little-endian integers enabled.
    #[must_use]
    pub fn minimal() -> Self {
        Self::new(InspectorConfig::minimal())
    }

    /// Inspect up to 16 bytes starting at `offset` in `data`.
    ///
    /// # Errors
    /// Returns [`InspectorError::OutOfRange`] if `offset >= data.len()`.
    pub fn inspect(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<InspectorResult, InspectorError> {
        if offset >= data.len() {
            return Err(InspectorError::OutOfRange(offset, data.len()));
        }
        let window_end = (offset + 16).min(data.len());
        let window = &data[offset..window_end];
        let raw_bytes = window.to_vec();
        let interpretations = self.build_interpretations(window);
        Ok(InspectorResult {
            offset,
            interpretations,
            raw_bytes,
        })
    }

    fn build_interpretations(&self, w: &[u8]) -> Vec<DataInterpretation> {
        let cfg = &self.config;
        let mut out = Vec::new();

        // 1-byte
        if !w.is_empty() {
            out.push(DataInterpretation::U8(w[0]));
            out.push(DataInterpretation::I8(w[0] as i8));
        }

        // Bit fields
        if cfg.bit_fields && !w.is_empty() {
            out.push(DataInterpretation::Bits8(bits8_str(w[0])));
        }

        // 2-byte
        if w.len() >= 2 {
            let bytes2: [u8; 2] = [w[0], w[1]];
            if cfg.little_endian {
                out.push(DataInterpretation::U16 {
                    value: u16::from_le_bytes(bytes2),
                    endian: Endian::Little,
                });
                out.push(DataInterpretation::I16 {
                    value: i16::from_le_bytes(bytes2),
                    endian: Endian::Little,
                });
                if cfg.bit_fields {
                    out.push(DataInterpretation::Bits16 {
                        value: bits16_str(u16::from_le_bytes(bytes2)),
                        endian: Endian::Little,
                    });
                }
            }
            if cfg.big_endian {
                out.push(DataInterpretation::U16 {
                    value: u16::from_be_bytes(bytes2),
                    endian: Endian::Big,
                });
                out.push(DataInterpretation::I16 {
                    value: i16::from_be_bytes(bytes2),
                    endian: Endian::Big,
                });
            }
        }

        // 4-byte
        if w.len() >= 4 {
            let bytes4: [u8; 4] = [w[0], w[1], w[2], w[3]];
            if cfg.little_endian {
                let u = u32::from_le_bytes(bytes4);
                let i = i32::from_le_bytes(bytes4);
                out.push(DataInterpretation::U32 { value: u, endian: Endian::Little });
                out.push(DataInterpretation::I32 { value: i, endian: Endian::Little });
                if cfg.floats {
                    out.push(DataInterpretation::F32 {
                        value: f32::from_le_bytes(bytes4),
                        endian: Endian::Little,
                    });
                }
            }
            if cfg.big_endian {
                let u = u32::from_be_bytes(bytes4);
                let i = i32::from_be_bytes(bytes4);
                out.push(DataInterpretation::U32 { value: u, endian: Endian::Big });
                out.push(DataInterpretation::I32 { value: i, endian: Endian::Big });
                if cfg.floats {
                    out.push(DataInterpretation::F32 {
                        value: f32::from_be_bytes(bytes4),
                        endian: Endian::Big,
                    });
                }
            }
            // IPv4
            if cfg.ip_addresses {
                out.push(DataInterpretation::Ipv4(format!(
                    "{}.{}.{}.{}",
                    w[0], w[1], w[2], w[3]
                )));
            }
        }

        // 8-byte
        if w.len() >= 8 {
            let bytes8: [u8; 8] = w[..8].try_into().unwrap();
            if cfg.little_endian {
                let u = u64::from_le_bytes(bytes8);
                let i = i64::from_le_bytes(bytes8);
                out.push(DataInterpretation::U64 { value: u, endian: Endian::Little });
                out.push(DataInterpretation::I64 { value: i, endian: Endian::Little });
                if cfg.floats {
                    out.push(DataInterpretation::F64 {
                        value: f64::from_le_bytes(bytes8),
                        endian: Endian::Little,
                    });
                }
                if cfg.timestamps {
                    // Unix timestamp
                    out.push(DataInterpretation::UnixTimestamp {
                        raw: u,
                        formatted: format_unix_ts(u),
                    });
                    // Windows FILETIME
                    out.push(DataInterpretation::FileTime {
                        raw: u,
                        formatted: format_filetime(u),
                    });
                }
            }
            if cfg.big_endian {
                let u = u64::from_be_bytes(bytes8);
                let i = i64::from_be_bytes(bytes8);
                out.push(DataInterpretation::U64 { value: u, endian: Endian::Big });
                out.push(DataInterpretation::I64 { value: i, endian: Endian::Big });
                if cfg.floats {
                    out.push(DataInterpretation::F64 {
                        value: f64::from_be_bytes(bytes8),
                        endian: Endian::Big,
                    });
                }
            }
        }

        // 16-byte
        if cfg.guid && w.len() >= 16 {
            out.push(DataInterpretation::Guid(format_guid(&w[..16])));
        }
        if cfg.ip_addresses && w.len() >= 16 {
            out.push(DataInterpretation::Ipv6(format_ipv6(&w[..16])));
        }

        // C-string
        if cfg.cstring {
            out.push(DataInterpretation::CString(
                extract_cstring(w, cfg.max_cstring_len),
            ));
        }

        out
    }
}

impl Default for DataInspector {
    fn default() -> Self {
        Self::all()
    }
}

// ─── Public convenience function ─────────────────────────────────────────────

/// Inspect bytes at `offset` in `data` using the default configuration.
///
/// # Errors
/// Returns an error if `offset` is out of range.
pub fn inspect_at(data: &[u8], offset: usize) -> Result<InspectorResult, InspectorError> {
    DataInspector::all().inspect(data, offset)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn bits8_str(v: u8) -> String {
    format!("{v:08b}")
}

fn bits16_str(v: u16) -> String {
    format!("{v:016b}")
}

fn format_unix_ts(secs: u64) -> String {
    // Very simple: compute rough date from epoch
    if secs > 0x7FFF_FFFF_FFFF_FFFF {
        return "invalid".to_string();
    }
    // Days since epoch
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    // Rough year calculation (ignoring leap years for simplicity)
    let year = 1970u64 + days / 365;
    let day_of_year = days % 365;
    // Month approximation
    let months = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    let mut d = day_of_year;
    for &m_days in &months {
        if d < m_days {
            break;
        }
        d -= m_days;
        month += 1;
    }
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn format_filetime(ft: u64) -> String {
    // Windows FILETIME: 100-nanosecond intervals since 1601-01-01
    // Convert to Unix epoch: subtract 11644473600 seconds worth of 100-ns intervals
    const FILETIME_TO_UNIX: u64 = 116_444_736_000_000_000;
    if ft < FILETIME_TO_UNIX {
        return "pre-1970".to_string();
    }
    let secs_since_epoch = (ft - FILETIME_TO_UNIX) / 10_000_000;
    format_unix_ts(secs_since_epoch)
}

fn format_guid(bytes: &[u8]) -> String {
    // Microsoft GUID: first 3 fields are LE, last 2 are BE
    let a = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let b = u16::from_le_bytes([bytes[4], bytes[5]]);
    let c = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{a:08X}-{b:04X}-{c:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn format_ipv6(bytes: &[u8]) -> String {
    let groups: Vec<String> = bytes
        .chunks(2)
        .map(|c| {
            let hi = c[0];
            let lo = c.get(1).copied().unwrap_or(0);
            format!("{hi:02X}{lo:02X}")
        })
        .collect();
    groups.join(":")
}

fn extract_cstring(bytes: &[u8], max_len: usize) -> String {
    let end = bytes
        .iter()
        .take(max_len)
        .position(|&b| b == 0)
        .unwrap_or(bytes.len().min(max_len));
    String::from_utf8_lossy(&bytes[..end])
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_at_basic() {
        let data = [0x01_u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = inspect_at(&data, 0).unwrap();
        assert_eq!(result.offset, 0);
        assert!(!result.interpretations.is_empty());
    }

    #[test]
    fn inspect_out_of_range() {
        let data = [0u8; 4];
        let err = inspect_at(&data, 10).unwrap_err();
        assert!(matches!(err, InspectorError::OutOfRange(10, 4)));
    }

    #[test]
    fn u8_interpretation() {
        let data = [0xAB_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspect_at(&data, 0).unwrap();
        let u8_val = result.get("uint8").unwrap();
        assert!(u8_val.value_str().contains("171"));
    }

    #[test]
    fn i8_negative() {
        let data = [0xFF_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspect_at(&data, 0).unwrap();
        let i8_val = result.get("int8").unwrap();
        assert!(i8_val.value_str().contains("-1"));
    }

    #[test]
    fn u16_le_interpretation() {
        let data = [0x34_u8, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspect_at(&data, 0).unwrap();
        let u16_vals: Vec<&DataInterpretation> = result
            .interpretations
            .iter()
            .filter(|i| i.type_name() == "uint16")
            .collect();
        assert!(!u16_vals.is_empty());
        // LE: 0x1234 = 4660
        let le = u16_vals.iter().find(|i| matches!(i, DataInterpretation::U16 { endian: Endian::Little, .. }));
        assert!(le.is_some());
    }

    #[test]
    fn u32_le_correct_value() {
        let v: u32 = 0xDEAD_BEEF;
        let data: Vec<u8> = {
            let mut d = v.to_le_bytes().to_vec();
            d.resize(16, 0);
            d
        };
        let result = inspect_at(&data, 0).unwrap();
        let u32_le = result.interpretations.iter().find(|i| {
            matches!(i, DataInterpretation::U32 { value, endian: Endian::Little } if *value == v)
        });
        assert!(u32_le.is_some());
    }

    #[test]
    fn guid_format() {
        let bytes: Vec<u8> = (0..16).collect();
        let result = inspect_at(&bytes, 0).unwrap();
        let guid = result.get("guid").unwrap();
        let s = guid.value_str();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert_eq!(s.matches('-').count(), 4);
    }

    #[test]
    fn ipv4_format() {
        let data = [192_u8, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspect_at(&data, 0).unwrap();
        let ipv4 = result.get("ipv4").unwrap();
        assert_eq!(ipv4.value_str(), "192.168.1.1");
    }

    #[test]
    fn cstring_extraction() {
        let mut data = b"hello\0".to_vec();
        data.resize(16, 0);
        let result = inspect_at(&data, 0).unwrap();
        let cs = result.get("c_string").unwrap();
        assert!(cs.value_str().contains("hello"));
    }

    #[test]
    fn bits8_format() {
        let data = [0b1010_1010_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspect_at(&data, 0).unwrap();
        let bits = result.get("bits8").unwrap();
        assert_eq!(bits.value_str(), "10101010");
    }

    #[test]
    fn unix_timestamp_format() {
        // 0 = 1970-01-01
        let data = [0u8; 16];
        let result = inspect_at(&data, 0).unwrap();
        let ts = result.get("unix_timestamp").unwrap();
        assert!(ts.value_str().contains("1970"));
    }

    #[test]
    fn data_interpretation_type_name() {
        let d = DataInterpretation::U8(0);
        assert_eq!(d.type_name(), "uint8");
        let d = DataInterpretation::Guid("test".to_string());
        assert_eq!(d.type_name(), "guid");
    }

    #[test]
    fn data_interpretation_display() {
        let d = DataInterpretation::U8(42);
        let s = d.to_string();
        assert!(s.contains("uint8"));
        assert!(s.contains("42"));
    }

    #[test]
    fn inspector_result_summary() {
        let data = [0u8; 16];
        let result = inspect_at(&data, 0).unwrap();
        let summary = result.summary();
        assert!(summary.contains("Offset:"));
    }

    #[test]
    fn minimal_config_only_le_integers() {
        let inspector = DataInspector::minimal();
        let data = [0x01_u8, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspector.inspect(&data, 0).unwrap();
        // No big-endian entries
        let be_count = result
            .interpretations
            .iter()
            .filter(|i| matches!(i, DataInterpretation::U16 { endian: Endian::Big, .. } | DataInterpretation::U32 { endian: Endian::Big, .. }))
            .count();
        assert_eq!(be_count, 0);
    }

    #[test]
    fn format_filetime_conversion() {
        // Approximate FILETIME for 2000-01-01
        let ft: u64 = 125_911_584_000_000_000;
        let s = format_filetime(ft);
        // Should produce a year around 2000
        assert!(s.contains("200"));
    }

    #[test]
    fn inspect_at_offset_nonzero() {
        let data = [0u8, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = inspect_at(&data, 2).unwrap();
        assert_eq!(result.offset, 2);
        let u8_val = result.get("uint8").unwrap();
        assert!(u8_val.value_str().contains("1"));
    }

    #[test]
    fn ipv6_format_correct_groups() {
        let data: Vec<u8> = (0..16).collect();
        let s = format_ipv6(&data);
        // 8 groups of 4 hex chars separated by colons
        assert_eq!(s.matches(':').count(), 7);
    }

    #[test]
    fn inspector_default_is_all() {
        let d = DataInspector::default();
        let data = [0u8; 16];
        let result = d.inspect(&data, 0).unwrap();
        // Should have many interpretations
        assert!(result.interpretations.len() > 10);
    }
}
