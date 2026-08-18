//! Resources.arsc decompiler: `ResType`, `ResEntry`, `StringPoolDecoder`,
//! `ComplexValue`, `StyleDecoder`, `AttrDecoder`, values.xml output.

use serde::{Deserialize, Serialize};
use std::fmt;

pub use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Binary `resources.arsc` primitives
//
// These back the real `parse_arsc` walk. They read exactly what the AOSP
// `ResourceTypes.h` layout defines and return a safe default when the slice is
// short, so a truncated or hostile `.arsc` yields an empty/absent field rather
// than a panic — this decoder is fed files from untrusted APKs.
// ─────────────────────────────────────────────────────────────────────────────

/// Chunk types this decoder dispatches on, from AOSP `ResourceTypes.h`.
///
/// ⚠ These MUST be constants in scope. Written as bare names in a `match`
/// without being in scope, Rust reads them as irrefutable BINDING PATTERNS:
/// the first arm then matches every chunk type and shadows the value it was
/// meant to compare against, silently. That is what happened here — the
/// compiler reported it only as "unused variable" and "unreachable pattern",
/// which reads like lint noise and is in fact a parser that treats every chunk
/// as a string pool.
use crate::arsc_parser::{RES_STRING_POOL_TYPE, RES_TABLE_PACKAGE_TYPE};

/// `RES_TABLE_TYPE` chunk type, from AOSP `ResourceTypes.h`.
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;

/// `ResTable_type::entryOffset` value meaning "this entry is absent".
const NO_ENTRY: u32 = 0xFFFF_FFFF;

/// `ResTable_entry::FLAG_COMPLEX` — the entry is a bag/map, not a scalar.
const ENTRY_FLAG_COMPLEX: u16 = 0x0001;

/// Little-endian `u32` at `off`, or 0 when the slice does not reach it.
///
/// Returning 0 rather than panicking is deliberate: every caller here is
/// walking offsets that came out of the file being parsed.
#[inline]
fn read_u32(data: &[u8], off: usize) -> u32 {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// Decode a fixed-width UTF-16LE field, stopping at the first NUL.
///
/// `ResTable_package::name` is a fixed 128-code-unit array padded with NULs, so
/// the length is not stored anywhere — the terminator is the only signal.
fn decode_utf16_fixed(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parse the string pool that starts at `off` inside `chunk`.
///
/// A missing or unparsable pool yields an empty pool rather than an error: a
/// package can legitimately carry no type or key strings, and a caller that
/// cannot resolve an index already falls back to `""`.
fn pool_at(chunk: &[u8], off: usize) -> StringPoolDecoder {
    chunk
        .get(off..)
        .and_then(|slice| StringPoolDecoder::parse(slice).ok())
        .unwrap_or_default()
}

/// Decode the `ResTable_config` fields this crate reports.
///
/// Only the five fields [`ResConfig`] carries are read; the rest of the 56-byte
/// structure is skipped rather than guessed at. A zeroed field means "any", the
/// AOSP default, and is reported as `None` — not as a value.
fn decode_config(cfg: &[u8]) -> ResConfig {
    /// Two packed ASCII bytes as a language/region code, `None` when zeroed.
    fn code(b: &[u8]) -> Option<String> {
        let (a, z) = (*b.first()?, *b.get(1)?);
        if a == 0 && z == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&[a, z]).to_string())
    }

    // ResTable_config: imsi(8) language(2) region(2) screenType{orientation(1)
    // touchscreen(1) density(2)} input{...} screenSize{...} version{sdk(2) minor(2)}
    let language = cfg.get(8..10).and_then(code);
    let region = cfg.get(10..12).and_then(code);
    let orientation = match cfg.get(12) {
        Some(1) => Some("port".to_string()),
        Some(2) => Some("land".to_string()),
        Some(3) => Some("square".to_string()),
        _ => None,
    };
    let density = cfg
        .get(14..16)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .and_then(|d| match d {
            0 => None,
            120 => Some("ldpi".to_string()),
            160 => Some("mdpi".to_string()),
            213 => Some("tvdpi".to_string()),
            240 => Some("hdpi".to_string()),
            320 => Some("xhdpi".to_string()),
            480 => Some("xxhdpi".to_string()),
            640 => Some("xxxhdpi".to_string()),
            0xFFFE => Some("anydpi".to_string()),
            0xFFFF => Some("nodpi".to_string()),
            other => Some(format!("{other}dpi")),
        });
    let sdk_version = cfg
        .get(24..26)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .and_then(|v| (v != 0).then(|| u32::from(v)));

    ResConfig { language, region, density, orientation, sdk_version }
}

/// Decode a `Res_value` at `off` into the typed value it represents.
///
/// The `dataType` codes are AOSP's. An unmodelled type is reported as
/// [`ResValue::Raw`] with its hex payload rather than being coerced into one of
/// the modelled variants — a wrong type is worse than an unparsed one.
fn decode_res_value(data: &[u8], off: usize, pool: &StringPoolDecoder) -> ResValue {
    // Res_value: size(2) res0(1) dataType(1) data(4)
    let Some(dt) = data.get(off + 3).copied() else {
        return ResValue::Raw(String::new());
    };
    let raw = read_u32(data, off + 4);
    match dt {
        0x00 => ResValue::Raw("@null".to_string()),
        0x01 => ResValue::Reference(format!("@0x{raw:08x}")),
        0x02 => ResValue::Reference(format!("?0x{raw:08x}")),
        0x03 => pool
            .get(raw as usize)
            .map_or_else(|| ResValue::Raw(format!("0x{raw:08x}")), |s| ResValue::String(s.to_string())),
        0x05 => ResValue::Dimen(format_complex_dimension(raw)),
        0x10 => ResValue::Integer(i32::from_le_bytes(raw.to_le_bytes())),
        0x12 => ResValue::Bool(raw != 0),
        0x1c..=0x1f => ResValue::Color(format!("#{raw:08x}")),
        _ => ResValue::Raw(format!("0x{raw:08x}")),
    }
}

/// Render a `TYPE_DIMENSION` payload as the `12dp`-style string AOSP defines.
fn format_complex_dimension(raw: u32) -> String {
    const UNITS: [&str; 8] = ["px", "dip", "sp", "pt", "in", "mm", "", ""];
    let unit = UNITS[(raw & 0x0F) as usize % UNITS.len()];
    let radix = (raw >> 4) & 0x03;
    let mantissa = raw >> 8;
    let shift = match radix {
        0 => 23.0_f32,
        1 => 16.0_f32,
        2 => 8.0_f32,
        _ => 0.0_f32,
    };
    let value = u32_to_f32_lossy(mantissa) / 2.0_f32.powf(shift);
    if (value.fract()).abs() < f32::EPSILON {
        format!("{}{unit}", value.trunc())
    } else {
        format!("{value}{unit}")
    }
}

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
    /// This walks the real chunk structure of the file: the `RES_TABLE` header,
    /// the global string pool, the `RES_TABLE_PACKAGE` chunk with its type- and
    /// key-string pools, and each `RES_TABLE_TYPE` chunk's entry table.  Every
    /// field of the returned [`ResPackage`] is decoded from `data`; nothing is
    /// supplied by this function.
    ///
    /// # Errors
    /// Returns a [`ResDecompilerError`] when the data is truncated, has bad
    /// magic, or contains no package chunk to describe.
    pub fn parse_arsc(data: &[u8]) -> Result<ResPackage, ResDecompilerError> {
        // ResTable_header: type u16, headerSize u16, size u32, packageCount u32.
        if data.len() < 12 {
            return Err(ResDecompilerError::Truncated(0));
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0x0002 {
            return Err(ResDecompilerError::InvalidMagic(u32::from(magic)));
        }
        let header_size = (u16::from_le_bytes([data[2], data[3]]) as usize).max(12);
        let declared = read_u32(data, 4) as usize;
        // Trust whichever bound is smaller: a declared size larger than the
        // buffer would let a crafted file walk off the end.
        let end = if declared == 0 {
            data.len()
        } else {
            declared.min(data.len())
        };

        let mut global_pool = StringPoolDecoder::default();
        let mut package: Option<ResPackage> = None;
        let mut off = header_size;
        while off + 8 <= end {
            let ctype = u16::from_le_bytes([data[off], data[off + 1]]);
            let csize = read_u32(data, off + 4) as usize;
            if csize < 8 || off + csize > end {
                break;
            }
            let chunk = &data[off..off + csize];
            match ctype {
                RES_STRING_POOL_TYPE => global_pool = StringPoolDecoder::parse(chunk)?,
                RES_TABLE_PACKAGE_TYPE => package = Some(Self::parse_package_chunk(chunk, &global_pool)?),
                _ => {}
            }
            off += csize;
        }

        let mut pkg = package.ok_or_else(|| {
            ResDecompilerError::Parse(
                "no RES_TABLE_PACKAGE (0x0200) chunk found; nothing in this blob describes a package"
                    .to_string(),
            )
        })?;
        pkg.string_pool = global_pool;
        Ok(pkg)
    }

    /// Decode one `RES_TABLE_PACKAGE` chunk into a [`ResPackage`].
    fn parse_package_chunk(
        chunk: &[u8],
        global: &StringPoolDecoder,
    ) -> Result<ResPackage, ResDecompilerError> {
        // type u16 | headerSize u16 | size u32 | id u32 | name u16[128]
        // | typeStrings u32 | lastPublicType u32 | keyStrings u32 | lastPublicKey u32
        const PKG_HEADER_MIN: usize = 284;
        if chunk.len() < PKG_HEADER_MIN {
            return Err(ResDecompilerError::Truncated(chunk.len()));
        }
        let header_size = (u16::from_le_bytes([chunk[2], chunk[3]]) as usize).max(PKG_HEADER_MIN);
        let package_id = read_u32(chunk, 8);
        let package_name = decode_utf16_fixed(&chunk[12..268]);
        let type_strings_off = read_u32(chunk, 268) as usize;
        let key_strings_off = read_u32(chunk, 276) as usize;

        let type_strings = pool_at(chunk, type_strings_off);
        let key_strings = pool_at(chunk, key_strings_off);

        let mut entries = Vec::new();
        let mut off = header_size;
        while off + 8 <= chunk.len() {
            let ctype = u16::from_le_bytes([chunk[off], chunk[off + 1]]);
            let csize = read_u32(chunk, off + 4) as usize;
            if csize < 8 || off + csize > chunk.len() {
                break;
            }
            if ctype == RES_TABLE_TYPE_TYPE {
                entries.extend(Self::parse_type_chunk(
                    &chunk[off..off + csize],
                    package_id,
                    &type_strings,
                    &key_strings,
                    global,
                ));
            }
            off += csize;
        }

        Ok(ResPackage {
            package_name,
            package_id,
            entries,
            string_pool: StringPoolDecoder::default(),
        })
    }

    /// Decode one `RES_TABLE_TYPE` chunk into the resource entries it holds.
    fn parse_type_chunk(
        tc: &[u8],
        package_id: u32,
        type_strings: &StringPoolDecoder,
        key_strings: &StringPoolDecoder,
        global: &StringPoolDecoder,
    ) -> Vec<ResEntry> {
        // type u16 | headerSize u16 | size u32 | id u8 | flags u8 | reserved u16
        // | entryCount u32 | entriesStart u32 | config
        if tc.len() < 20 {
            return Vec::new();
        }
        let header_size = u16::from_le_bytes([tc[2], tc[3]]) as usize;
        let type_id = u32::from(tc[8]);
        let entry_count = read_u32(tc, 12) as usize;
        let entries_start = read_u32(tc, 16) as usize;
        if header_size < 20 || header_size > tc.len() {
            return Vec::new();
        }

        let type_name = type_id
            .checked_sub(1)
            .and_then(|i| type_strings.get(i as usize))
            .unwrap_or("")
            .to_string();
        let res_type = type_name.parse::<ResType>().unwrap_or(ResType::Unknown);
        let config = decode_config(&tc[20..header_size]);

        // Cap the file-supplied count against what the offset table can hold.
        let entry_count = entry_count.min(tc.len().saturating_sub(header_size) / 4);
        let mut out = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let off_pos = header_size + i * 4;
            let entry_off = read_u32(tc, off_pos);
            if entry_off == NO_ENTRY {
                continue;
            }
            let ep = entries_start.saturating_add(entry_off as usize);
            if ep + 8 > tc.len() {
                continue;
            }
            let entry_size = u16::from_le_bytes([tc[ep], tc[ep + 1]]) as usize;
            let entry_flags = u16::from_le_bytes([tc[ep + 2], tc[ep + 3]]);
            let key_index = read_u32(tc, ep + 4) as usize;
            let name = key_strings.get(key_index).unwrap_or("").to_string();
            let value = if entry_flags & ENTRY_FLAG_COMPLEX != 0 {
                // A bag/map entry: its members live in a separate table this
                // decoder does not walk, so name the bag rather than invent a
                // scalar for it.
                ResValue::Reference(format!("{type_name}/{name}"))
            } else {
                decode_res_value(tc, ep + entry_size.max(8), global)
            };
            out.push(ResEntry {
                name,
                res_id: (package_id << 24) | (type_id << 16) | (i as u32),
                res_type,
                value,
                config: config.clone(),
            });
        }
        out
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
    /// NOTE: a hand-written fixture for this crate's own tests. It is not
    /// derived from any input and is not reachable from the MCP tool surface;
    /// never report it to a user as the analysis of a real file.
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
    fn test_res_decompiler_parse_arsc_header_without_package_is_an_error() {
        // ⚠ This asserted `is_ok()`. It passed only because `parse_arsc` used to
        // INVENT a package: 64 zero bytes carrying nothing but a RES_TABLE type
        // word describe no package name, no types and no entries, so "ok" was a
        // fabricated answer and the test was pinning the fabrication.
        //
        // The real walk reports what is missing instead.
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(&0x0002u16.to_le_bytes());
        let err = ResDecompiler::parse_arsc(&data)
            .expect_err("a table header with no RES_TABLE_PACKAGE chunk describes no package");
        let msg = err.to_string();
        assert!(
            msg.contains("RES_TABLE_PACKAGE"),
            "the error must name the missing chunk, got: {msg}"
        );
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
