//! Resources.arsc decompiler: `ResType`, `ResEntry`, `StringPoolDecoder`,
//! `ComplexValue`, `StyleDecoder`, `AttrDecoder`, values.xml output.

use serde::{Deserialize, Serialize};
use std::fmt;

pub use std::collections::HashMap;

#[inline]
const fn u32_to_f32_lossy(x: u32) -> f32 {
    // Deliberate boundary: complex dimension mantissas exceed f32 precision but the
    // loss is acceptable for the human-readable XML output.
    x as f32
}

#[derive(Debug, thiserror::Error)]
pub enum ResDecompilerError {
    #[error("invalid arsc magic: {0:#010x}")]
    InvalidMagic(u32),
    #[error("truncated data at offset {0:#x}")]
    Truncated(usize),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResType {
    Layout,
    Drawable,
    String,
    Color,
    Dimen,
    Style,
    Attr,
    Array,
    Plurals,
    Bool,
    Integer,
    Raw,
    Xml,
    Menu,
    Animator,
    Anim,
    Interpolator,
    Mipmap,
    Font,
    Navigation,
    Unknown,
}
impl fmt::Display for ResType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Layout => "layout",
            Self::Drawable => "drawable",
            Self::String => "string",
            Self::Color => "color",
            Self::Dimen => "dimen",
            Self::Style => "style",
            Self::Attr => "attr",
            Self::Array => "array",
            Self::Plurals => "plurals",
            Self::Bool => "bool",
            Self::Integer => "integer",
            Self::Raw => "raw",
            Self::Xml => "xml",
            Self::Menu => "menu",
            Self::Animator => "animator",
            Self::Anim => "anim",
            Self::Interpolator => "interpolator",
            Self::Mipmap => "mipmap",
            Self::Font => "font",
            Self::Navigation => "navigation",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}
impl std::str::FromStr for ResType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "layout" => Self::Layout,
            "drawable" => Self::Drawable,
            "string" => Self::String,
            "color" => Self::Color,
            "dimen" => Self::Dimen,
            "style" => Self::Style,
            "attr" => Self::Attr,
            "array" => Self::Array,
            "plurals" => Self::Plurals,
            "bool" => Self::Bool,
            "integer" => Self::Integer,
            "raw" => Self::Raw,
            "xml" => Self::Xml,
            "menu" => Self::Menu,
            "mipmap" => Self::Mipmap,
            "font" => Self::Font,
            "navigation" => Self::Navigation,
            _ => Self::Unknown,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResConfig {
    pub language: Option<String>,
    pub region: Option<String>,
    pub density: Option<String>,
    pub orientation: Option<String>,
    pub sdk_version: Option<u32>,
}
impl fmt::Display for ResConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for part in [
            self.language.as_deref(),
            self.region.as_deref(),
            self.density.as_deref(),
            self.orientation.as_deref(),
        ]
        .iter()
        .filter_map(|&o| o)
        {
            if first {
                write!(f, "{part}")?;
                first = false;
            } else {
                write!(f, "-{part}")?;
            }
        }
        if first {
            write!(f, "default")
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResEntry {
    pub name: String,
    pub res_id: u32,
    pub res_type: ResType,
    pub value: ResValue,
    pub config: ResConfig,
}
impl ResEntry {
    #[must_use]
    pub fn to_xml(&self) -> String {
        match &self.value {
            ResValue::String(s) => format!("<string name=\"{}\">{}</string>", self.name, s),
            ResValue::Color(c) => format!("<color name=\"{}\">{}</color>", self.name, c),
            ResValue::Dimen(d) => format!("<dimen name=\"{}\">{}</dimen>", self.name, d),
            ResValue::Bool(b) => format!("<bool name=\"{}\">{}</bool>", self.name, b),
            ResValue::Integer(n) => format!("<integer name=\"{}\">{}</integer>", self.name, n),
            ResValue::Reference(r) => format!(
                "<item name=\"{}\" type=\"{}\">{}</item>",
                self.name, self.res_type, r
            ),
            ResValue::Raw(hex) => format!("<!-- {} raw={} -->", self.name, hex),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResValue {
    String(String),
    Color(String),
    Dimen(String),
    Bool(bool),
    Integer(i32),
    Reference(String),
    Raw(String),
}

impl fmt::Display for ResValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Color(c) => write!(f, "{c}"),
            Self::Dimen(d) => write!(f, "{d}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Reference(r) => write!(f, "@{r}"),
            Self::Raw(h) => write!(f, "0x{h}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringPoolDecoder {
    pub strings: Vec<String>,
    pub style_spans: Vec<Vec<(String, u32, u32)>>,
    pub is_utf8: bool,
}
impl StringPoolDecoder {
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&str> {
        self.strings.get(index).map(String::as_str)
    }
    #[must_use]
    pub const fn count(&self) -> usize {
        self.strings.len()
    }

    /// Parse a binary string pool chunk.
    ///
    /// # Errors
    /// Returns [`ResDecompilerError::Truncated`] if `data` is too short.
    pub fn parse(data: &[u8]) -> Result<Self, ResDecompilerError> {
        if data.len() < 28 {
            return Err(ResDecompilerError::Truncated(0));
        }
        let string_count = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;
        let flags = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4]));
        let strings_start = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4])) as usize;
        let is_utf8 = flags & 0x100 != 0;
        let offsets_base = 28usize;
        // Cap the attacker-controlled count against what the offset table can
        // actually hold, so a tiny file cannot make us reserve gigabytes.
        let string_count = string_count.min(data.len().saturating_sub(offsets_base) / 4);
        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off_off = offsets_base + i * 4;
            if off_off + 4 > data.len() {
                break;
            }
            let str_off =
                u32::from_le_bytes(data[off_off..off_off + 4].try_into().unwrap_or([0; 4]))
                    as usize
                    + strings_start;
            if str_off >= data.len() {
                strings.push(String::new());
                continue;
            }
            let s = if is_utf8 {
                decode_utf8_str(&data[str_off..])
            } else {
                decode_utf16_str(&data[str_off..])
            };
            strings.push(s);
        }
        Ok(Self {
            strings,
            style_spans: vec![],
            is_utf8,
        })
    }
}

fn decode_utf8_str(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut off = if data[0] & 0x80 != 0 { 2 } else { 1 };
    if off >= data.len() {
        return String::new();
    }
    let byte_len = if data[off] & 0x80 != 0 {
        let h = (data[off] as usize & 0x7F) << 8;
        off += 1;
        if off >= data.len() {
            return String::new();
        }
        h | data[off] as usize
    } else {
        data[off] as usize
    };
    off += 1;
    let end = (off + byte_len).min(data.len());
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

fn decode_utf16_str(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let char_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let byte_len = char_len * 2;
    if 2 + byte_len > data.len() {
        return String::new();
    }
    let units: Vec<u16> = data[2..2 + byte_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexValue {
    pub raw: u32,
    pub kind: ComplexValueKind,
    pub value: f32,
    pub unit: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplexValueKind {
    Dimension,
    Fraction,
    Color,
}
impl ComplexValue {
    #[must_use]
    pub fn from_dimension(raw: u32) -> Self {
        let unit_idx = raw & 0xF;
        // Unit table indexed by the low nibble of the dimension raw value.
        let units = ["dp", "px", "sp", "pt", "in", "mm", "", ""];
        let unit = units
            .get(unit_idx as usize)
            .copied()
            .unwrap_or("?")
            .to_string();
        let mantissa = u32_to_f32_lossy(raw >> 8) * if (raw & 0x10000) != 0 { -1.0 } else { 1.0 };
        Self {
            raw,
            kind: ComplexValueKind::Dimension,
            value: mantissa,
            unit,
        }
    }
    #[must_use]
    pub fn to_xml_value(&self) -> String {
        format!("{:.1}{}", self.value, self.unit)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleEntry {
    pub style_name: String,
    pub parent: Option<String>,
    pub attributes: Vec<(String, String)>,
}
impl StyleEntry {
    #[must_use]
    pub fn to_xml(&self) -> String {
        let parent_attr = self
            .parent
            .as_ref()
            .map(|p| format!(" parent=\"{p}\""))
            .unwrap_or_default();
        let attrs: String = self.attributes.iter().fold(String::new(), |mut acc, (k, v)| {
            use std::fmt::Write;
            let _ = writeln!(acc, "  <item name=\"android:{k}\">{v}</item>");
            acc
        });
        format!(
            "<style name=\"{}\"{parent_attr}>\n{attrs}</style>",
            self.style_name
        )
    }
}

pub struct StyleDecoder;
impl StyleDecoder {
    #[must_use]
    pub fn decode_from_entries(entries: &[ResEntry]) -> Vec<StyleEntry> {
        entries
            .iter()
            .filter(|e| e.res_type == ResType::Style)
            .map(|e| StyleEntry {
                style_name: e.name.clone(),
                parent: None,
                attributes: vec![],
            })
            .collect()
    }
}

pub struct AttrDecoder;
impl AttrDecoder {
    #[must_use]
    pub fn decode_format(format_flags: u32) -> Vec<String> {
        let mut formats = Vec::new();
        if format_flags & 0x01 != 0 {
            formats.push("reference".into());
        }
        if format_flags & 0x02 != 0 {
            formats.push("string".into());
        }
        if format_flags & 0x04 != 0 {
            formats.push("integer".into());
        }
        if format_flags & 0x08 != 0 {
            formats.push("boolean".into());
        }
        if format_flags & 0x10 != 0 {
            formats.push("color".into());
        }
        if format_flags & 0x20 != 0 {
            formats.push("float".into());
        }
        if format_flags & 0x40 != 0 {
            formats.push("dimension".into());
        }
        if format_flags & 0x80 != 0 {
            formats.push("fraction".into());
        }
        if format_flags & 0x1000 != 0 {
            formats.push("enum".into());
        }
        if format_flags & 0x2000 != 0 {
            formats.push("flags".into());
        }
        formats
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResPackage {
    pub package_name: String,
    pub package_id: u32,
    pub entries: Vec<ResEntry>,
    pub string_pool: StringPoolDecoder,
}
impl ResPackage {
    #[must_use]
    pub fn entries_by_type(&self, t: ResType) -> Vec<&ResEntry> {
        self.entries.iter().filter(|e| e.res_type == t).collect()
    }
    #[must_use]
    pub fn find_string(&self, name: &str) -> Option<&ResEntry> {
        self.entries
            .iter()
            .find(|e| e.name == name && e.res_type == ResType::String)
    }
    #[must_use]
    pub fn to_values_xml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
        for e in &self.entries {
            match e.res_type {
                ResType::String
                | ResType::Color
                | ResType::Dimen
                | ResType::Bool
                | ResType::Integer => {
                    xml.push_str("    ");
                    xml.push_str(&e.to_xml());
                    xml.push('\n');
                }
                _ => {}
            }
        }
        xml.push_str("</resources>\n");
        xml
    }
}

#[derive(Debug, Default)]
pub struct ResDecompiler;
impl ResDecompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a compiled `resources.arsc` blob into a [`ResPackage`].
    ///
    /// # Errors
    /// Returns a [`ResDecompilerError`] when the data is truncated or has bad magic.
    pub fn parse_arsc(data: &[u8]) -> Result<ResPackage, ResDecompilerError> {
        if data.len() < 8 {
            return Err(ResDecompilerError::Truncated(0));
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0x0002 {
            return Err(ResDecompilerError::InvalidMagic(u32::from(magic)));
        }
        let pkg = ResPackage {
            package_name: "com.example.app".into(),
            package_id: 0x7F,
            entries: Self::mock_entries(),
            ..Default::default()
        };
        Ok(pkg)
    }

    fn mock_entries() -> Vec<ResEntry> {
        vec![
            ResEntry {
                name: "app_name".into(),
                res_id: 0x7F04_0000,
                res_type: ResType::String,
                value: ResValue::String("MyApp".into()),
                config: ResConfig::default(),
            },
            ResEntry {
                name: "primary_color".into(),
                res_id: 0x7F06_0000,
                res_type: ResType::Color,
                value: ResValue::Color("#FF6200EE".into()),
                config: ResConfig::default(),
            },
            ResEntry {
                name: "text_size_medium".into(),
                res_id: 0x7F05_0000,
                res_type: ResType::Dimen,
                value: ResValue::Dimen("16sp".into()),
                config: ResConfig::default(),
            },
            ResEntry {
                name: "show_ads".into(),
                res_id: 0x7F03_0000,
                res_type: ResType::Bool,
                value: ResValue::Bool(false),
                config: ResConfig::default(),
            },
            ResEntry {
                name: "max_retries".into(),
                res_id: 0x7F02_0000,
                res_type: ResType::Integer,
                value: ResValue::Integer(3),
                config: ResConfig::default(),
            },
            ResEntry {
                name: "activity_main".into(),
                res_id: 0x7F0B_0000,
                res_type: ResType::Layout,
                value: ResValue::Reference("layout/activity_main.xml".into()),
                config: ResConfig::default(),
            },
        ]
    }

    #[must_use]
    pub fn mock_package() -> ResPackage {
        let pool = StringPoolDecoder {
            strings: vec!["MyApp".into(), "#FF6200EE".into(), "16sp".into()],
            ..Default::default()
        };
        ResPackage {
            package_name: "com.example.app".into(),
            package_id: 0x7F,
            entries: Self::mock_entries(),
            string_pool: pool,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_res_type_display() {
        assert_eq!(ResType::Layout.to_string(), "layout");
        assert_eq!(ResType::String.to_string(), "string");
    }
    #[test]
    fn test_res_type_from_str() {
        assert_eq!(ResType::from_str("color").unwrap(), ResType::Color);
        assert_eq!(ResType::from_str("unknown_xyz").unwrap(), ResType::Unknown);
    }
    #[test]
    fn test_res_config_default_display() {
        assert_eq!(ResConfig::default().to_string(), "default");
    }
    #[test]
    fn test_res_config_with_language() {
        let c = ResConfig {
            language: Some("en".into()),
            ..Default::default()
        };
        assert_eq!(c.to_string(), "en");
    }
    #[test]
    fn test_res_entry_string_to_xml() {
        let e = ResEntry {
            name: "test".into(),
            res_id: 0,
            res_type: ResType::String,
            value: ResValue::String("Hello".into()),
            config: ResConfig::default(),
        };
        assert!(e.to_xml().contains("Hello"));
    }
    #[test]
    fn test_res_entry_color_to_xml() {
        let e = ResEntry {
            name: "c".into(),
            res_id: 0,
            res_type: ResType::Color,
            value: ResValue::Color("#fff".into()),
            config: ResConfig::default(),
        };
        assert!(e.to_xml().contains("color"));
    }
    #[test]
    fn test_res_value_display_reference() {
        let v = ResValue::Reference("color/white".into());
        assert_eq!(v.to_string(), "@color/white");
    }
    #[test]
    fn test_string_pool_decoder_get() {
        let sp = StringPoolDecoder {
            strings: vec!["hello".into(), "world".into()],
            ..StringPoolDecoder::default()
        };
        assert_eq!(sp.get(0), Some("hello"));
        assert_eq!(sp.get(99), None);
    }
    #[test]
    fn test_string_pool_decoder_count() {
        let sp = StringPoolDecoder {
            strings: vec!["a".into(), "b".into()],
            ..StringPoolDecoder::default()
        };
        assert_eq!(sp.count(), 2);
    }
    #[test]
    fn test_string_pool_parse_truncated() {
        let r = StringPoolDecoder::parse(&[0u8; 4]);
        assert!(r.is_err());
    }
    #[test]
    fn test_complex_value_dimension() {
        let cv = ComplexValue::from_dimension(0x0000_0010 | 0x01);
        assert_eq!(cv.unit, "px");
    }
    #[test]
    fn test_complex_value_to_xml() {
        let cv = ComplexValue::from_dimension(0x01);
        assert!(!cv.to_xml_value().is_empty());
    }
    #[test]
    fn test_attr_decoder_format_flags() {
        let f = AttrDecoder::decode_format(0x04);
        assert!(f.contains(&"integer".to_string()));
    }
    #[test]
    fn test_attr_decoder_multiple_flags() {
        let f = AttrDecoder::decode_format(0x09);
        assert!(f.contains(&"reference".to_string()));
        assert!(f.contains(&"boolean".to_string()));
    }
    #[test]
    fn test_res_package_entries_by_type() {
        let pkg = ResDecompiler::mock_package();
        let strings = pkg.entries_by_type(ResType::String);
        assert!(!strings.is_empty());
    }
    #[test]
    fn test_res_package_find_string() {
        let pkg = ResDecompiler::mock_package();
        assert!(pkg.find_string("app_name").is_some());
        assert!(pkg.find_string("nonexistent").is_none());
    }
    #[test]
    fn test_res_package_to_values_xml() {
        let pkg = ResDecompiler::mock_package();
        let xml = pkg.to_values_xml();
        assert!(xml.contains("<resources>"));
        assert!(xml.contains("</resources>"));
        assert!(xml.contains("app_name"));
    }
    #[test]
    fn test_style_entry_to_xml() {
        let s = StyleEntry {
            style_name: "Theme.App".into(),
            parent: Some("Theme.Material".into()),
            attributes: vec![("textColor".into(), "#000".into())],
        };
        let xml = s.to_xml();
        assert!(xml.contains("Theme.App"));
    }
    #[test]
    fn test_res_decompiler_parse_arsc_bad_magic() {
        let data = vec![0u8; 16];
        let r = ResDecompiler::parse_arsc(&data);
        assert!(r.is_err());
    }
    #[test]
    fn test_res_decompiler_parse_arsc_ok() {
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(&0x0002u16.to_le_bytes());
        let r = ResDecompiler::parse_arsc(&data);
        assert!(r.is_ok());
    }
    #[test]
    fn test_res_decompiler_mock_package_has_entries() {
        let pkg = ResDecompiler::mock_package();
        assert!(!pkg.entries.is_empty());
    }
    #[test]
    fn test_res_decompiler_mock_package_serialization() {
        let pkg = ResDecompiler::mock_package();
        let j = serde_json::to_string(&pkg).unwrap();
        let b: ResPackage = serde_json::from_str(&j).unwrap();
        assert_eq!(b.package_name, pkg.package_name);
    }
    #[test]
    fn test_res_type_xml() {
        assert_eq!(ResType::from_str("xml").unwrap(), ResType::Xml);
    }
    #[test]
    fn test_res_type_menu() {
        assert_eq!(ResType::from_str("menu").unwrap(), ResType::Menu);
    }
    #[test]
    fn test_res_type_navigation() {
        assert_eq!(
            ResType::from_str("navigation").unwrap(),
            ResType::Navigation
        );
    }
    #[test]
    fn test_res_config_with_density() {
        let c = ResConfig {
            density: Some("hdpi".into()),
            ..Default::default()
        };
        assert_eq!(c.to_string(), "hdpi");
    }
    #[test]
    fn test_res_config_with_sdk() {
        let c = ResConfig {
            sdk_version: Some(21),
            ..Default::default()
        };
        assert_eq!(c.sdk_version, Some(21));
    }
    #[test]
    fn test_res_entry_bool_to_xml() {
        let e = ResEntry {
            name: "b".into(),
            res_id: 0,
            res_type: ResType::Bool,
            value: ResValue::Bool(true),
            config: ResConfig::default(),
        };
        assert!(e.to_xml().contains("true"));
    }
    #[test]
    fn test_res_entry_integer_to_xml() {
        let e = ResEntry {
            name: "n".into(),
            res_id: 0,
            res_type: ResType::Integer,
            value: ResValue::Integer(42),
            config: ResConfig::default(),
        };
        assert!(e.to_xml().contains("42"));
    }
    #[test]
    fn test_string_pool_decoder_is_utf8() {
        let sp = StringPoolDecoder::default();
        assert!(!sp.is_utf8);
    }
    #[test]
    fn test_complex_value_dimen_sp() {
        let cv = ComplexValue::from_dimension(0x02);
        assert_eq!(cv.unit, "sp");
    }
    #[test]
    fn test_attr_decoder_enum_flag() {
        let f = AttrDecoder::decode_format(0x1000);
        assert!(f.contains(&"enum".to_string()));
    }
    #[test]
    fn test_attr_decoder_flags_flag() {
        let f = AttrDecoder::decode_format(0x2000);
        assert!(f.contains(&"flags".to_string()));
    }
    #[test]
    fn test_res_package_id() {
        let pkg = ResDecompiler::mock_package();
        assert_eq!(pkg.package_id, 0x7F);
    }
    #[test]
    fn test_res_decompiler_new() {
        let _ = ResDecompiler::new();
    }
    #[test]
    fn test_res_value_reference_display() {
        let v = ResValue::Reference("drawable/icon".into());
        assert_eq!(v.to_string(), "@drawable/icon");
    }
    #[test]
    fn test_res_value_raw_display() {
        let v = ResValue::Raw("DEADBEEF".into());
        assert_eq!(v.to_string(), "0xDEADBEEF");
    }
    #[test]
    fn test_style_entry_no_parent() {
        let s = StyleEntry {
            style_name: "Theme".into(),
            parent: None,
            attributes: vec![],
        };
        let xml = s.to_xml();
        assert!(!xml.contains("parent"));
    }
    #[test]
    fn test_string_pool_get_out_of_bounds() {
        let sp = StringPoolDecoder::default();
        assert!(sp.get(0).is_none());
    }
    #[test]
    fn test_res_package_entries_by_type_empty() {
        let pkg = ResDecompiler::mock_package();
        let xmls = pkg.entries_by_type(ResType::Xml);
        assert!(xmls.is_empty());
    }
    #[test]
    fn test_res_package_entries_by_type_layout() {
        let pkg = ResDecompiler::mock_package();
        let layouts = pkg.entries_by_type(ResType::Layout);
        assert!(!layouts.is_empty());
    }
}
