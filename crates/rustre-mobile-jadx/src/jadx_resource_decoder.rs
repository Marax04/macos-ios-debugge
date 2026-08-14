//! `jadx_resource_decoder` — Decode Android resources from a JADX output tree.
//!
//! JADX emits decoded resources under `<output>/resources/`.  This module walks
//! that directory, classifies each file, and parses XML-format resources
//! (strings, colors, dimensions, styles, layouts) into structured Rust types
//! without needing the Android SDK or a JVM.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::JadxError;

// ─────────────────────────────────────────────────────────────────────────────
// ResourceType
// ─────────────────────────────────────────────────────────────────────────────

/// High-level category of an Android resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    /// `res/values/strings.xml` – string entries.
    String,
    /// `res/values/colors.xml` – ARGB color entries.
    Color,
    /// `res/values/dimens.xml` – dimension (dp/sp/px) entries.
    Dimension,
    /// `res/values/styles.xml` – style/theme entries.
    Style,
    /// `res/layout/*.xml` – layout XML files.
    Layout,
    /// `res/drawable/*` – drawable XML or bitmap.
    Drawable,
    /// `res/menu/*.xml` – menu XML.
    Menu,
    /// `res/anim/*.xml` or `res/animator/*.xml`.
    Animation,
    /// `res/raw/*` – arbitrary raw files.
    Raw,
    /// `res/xml/*.xml` – miscellaneous XML.
    Xml,
    /// `assets/` – uncompressed asset files.
    Asset,
    /// Anything else.
    Unknown,
}

impl ResourceType {
    /// Classify a resource path relative to the resources root.
    #[must_use]
    pub fn from_path(rel: &Path) -> Self {
        let components: Vec<&str> = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        match components.first().copied() {
            Some("assets") => Self::Asset,
            Some("res") => {
                let dir = components.get(1).copied().unwrap_or("");
                let dir_base = dir.split('-').next().unwrap_or(dir);
                match dir_base {
                    "layout" => Self::Layout,
                    "drawable" => Self::Drawable,
                    "menu" => Self::Menu,
                    "anim" | "animator" => Self::Animation,
                    "raw" => Self::Raw,
                    "xml" => Self::Xml,
                    "values" => {
                        // refine by filename
                        let fname = components.last().copied().unwrap_or("");
                        if fname.contains("string") { Self::String }
                        else if fname.contains("color") { Self::Color }
                        else if fname.contains("dimen") { Self::Dimension }
                        else if fname.contains("style") || fname.contains("theme") { Self::Style }
                        else { Self::Xml }
                    }
                    _ => Self::Unknown,
                }
            }
            _ => Self::Unknown,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringEntry / ColorEntry / DimenEntry / StyleEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A `<string name="key">value</string>` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub name: String,
    pub value: String,
    pub translatable: bool,
}

/// A `<color name="key">#AARRGGBB</color>` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorEntry {
    pub name: String,
    /// Raw value string (e.g. `"#FF0000"` or `"@color/base"`).
    pub value: String,
    /// Decoded ARGB (if the value is a literal hex color).
    pub argb: Option<u32>,
}

/// A `<dimen name="key">16dp</dimen>` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimenEntry {
    pub name: String,
    pub value: String,
    /// Numeric magnitude (e.g. `16.0`).
    pub magnitude: Option<f64>,
    /// Unit (e.g. `"dp"`, `"sp"`, `"px"`).
    pub unit: Option<String>,
}

/// A `<style name="AppTheme" parent="…">` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleEntry {
    pub name: String,
    pub parent: Option<String>,
    /// `<item name="key">value</item>` pairs.
    pub items: Vec<(String, String)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodedResource
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded resource artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedResource {
    /// Resource type category.
    pub kind: ResourceType,
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Path relative to the resources root.
    pub rel_path: PathBuf,
    /// Decoded content (varies by kind).
    pub content: ResourceContent,
}

/// Polymorphic decoded content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceContent {
    /// Parsed string table.
    Strings(Vec<StringEntry>),
    /// Parsed color table.
    Colors(Vec<ColorEntry>),
    /// Parsed dimension table.
    Dimensions(Vec<DimenEntry>),
    /// Parsed style list.
    Styles(Vec<StyleEntry>),
    /// Raw XML text.
    Xml(String),
    /// Binary / non-XML file (base64-encoded for serialization).
    Binary { size: usize, sha256_hex: String },
    /// Unrecognised.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodeStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of a decode run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecodeStats {
    pub total_files: usize,
    pub decoded: usize,
    pub failed: usize,
    pub strings: usize,
    pub colors: usize,
    pub dimensions: usize,
    pub styles: usize,
    pub layouts: usize,
    pub drawables: usize,
    pub assets: usize,
    pub other: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxResourceDecoder
// ─────────────────────────────────────────────────────────────────────────────

/// Walks a JADX resource output directory and decodes all resources.
///
/// JADX typically places resources under `<output>/resources/`.
///
/// # Example
///
/// ```no_run
/// use rustre_mobile_jadx::jadx_resource_decoder::JadxResourceDecoder;
/// use std::path::Path;
///
/// let decoder = JadxResourceDecoder::new();
/// let (resources, stats) = decoder.decode_dir(Path::new("/tmp/jadx_out")).unwrap();
/// println!("Decoded {} resources ({} strings)", resources.len(), stats.strings);
/// ```
#[derive(Debug, Clone)]
pub struct JadxResourceDecoder {
    /// Maximum file size to attempt XML parsing (in bytes). Files larger than
    /// this are recorded as `Binary`.
    pub max_xml_size: usize,
    /// Whether to hash binary files (SHA-256). Set to false to skip hashing.
    pub hash_binaries: bool,
}

impl Default for JadxResourceDecoder {
    fn default() -> Self {
        Self {
            max_xml_size: 4 * 1024 * 1024, // 4 MiB
            hash_binaries: false,
        }
    }
}

impl JadxResourceDecoder {
    /// Create a decoder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode all resources in a JADX output directory.
    ///
    /// The method searches both `<dir>/resources/` and `<dir>/` for resource
    /// files.
    ///
    /// # Errors
    /// Returns `JadxError::Io` if the root directory cannot be read.
    pub fn decode_dir(&self, dir: &Path) -> Result<(Vec<DecodedResource>, DecodeStats), JadxError> {
        let res_root = dir.join("resources");
        let search_root = if res_root.is_dir() { res_root } else { dir.to_path_buf() };

        let mut resources = Vec::new();
        let mut stats = DecodeStats::default();

        self.walk(&search_root, &search_root, &mut resources, &mut stats)?;

        stats.total_files = stats.decoded + stats.failed;
        Ok((resources, stats))
    }

    /// Decode a single file.
    ///
    /// # Errors
    /// Returns `JadxError::Io` if the file cannot be read.
    pub fn decode_file(&self, root: &Path, path: &Path) -> Result<DecodedResource, JadxError> {
        let rel_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        let kind = ResourceType::from_path(&rel_path);
        let content = self.decode_content(&kind, path)?;
        Ok(DecodedResource {
            kind,
            path: path.to_path_buf(),
            rel_path,
            content,
        })
    }

    // ── Private helpers ────────────────────────────────────────────────────

    fn walk(
        &self,
        root: &Path,
        current: &Path,
        out: &mut Vec<DecodedResource>,
        stats: &mut DecodeStats,
    ) -> Result<(), JadxError> {
        self.walk_inner(root, current, out, stats, 0)
    }

    fn walk_inner(
        &self,
        root: &Path,
        current: &Path,
        out: &mut Vec<DecodedResource>,
        stats: &mut DecodeStats,
        depth: usize,
    ) -> Result<(), JadxError> {
        const MAX_DEPTH: usize = 64;
        if depth > MAX_DEPTH {
            return Err(JadxError::Io(format!(
                "resource directory tree too deep (>{MAX_DEPTH} levels) at {}",
                current.display()
            )));
        }
        let entries = std::fs::read_dir(current)
            .map_err(|e| JadxError::Io(format!("read_dir {}: {e}", current.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| JadxError::Io(e.to_string()))?;
            let path = entry.path();
            if path.is_dir() {
                self.walk_inner(root, &path, out, stats, depth + 1)?;
            } else {
                match self.decode_file(root, &path) {
                    Ok(res) => {
                        update_stats(stats, &res);
                        out.push(res);
                        stats.decoded += 1;
                    }
                    Err(_) => stats.failed += 1,
                }
            }
        }
        Ok(())
    }

    fn decode_content(&self, kind: &ResourceType, path: &Path) -> Result<ResourceContent, JadxError> {
        let is_xml = path.extension().and_then(|e| e.to_str()) == Some("xml");
        if !is_xml {
            let file_len = std::fs::metadata(path)
                .map_err(|e| JadxError::Io(e.to_string()))?
                .len();
            let size = usize::try_from(file_len)
                .unwrap_or(usize::MAX);
            let sha256_hex = if self.hash_binaries {
                sha256_file(path)
            } else {
                String::new()
            };
            return Ok(ResourceContent::Binary { size, sha256_hex });
        }

        let meta = std::fs::metadata(path).map_err(|e| JadxError::Io(e.to_string()))?;
        let file_len = meta.len();
        let file_size = usize::try_from(file_len).unwrap_or(usize::MAX);
        if file_size > self.max_xml_size {
            return Ok(ResourceContent::Binary {
                size: file_size,
                sha256_hex: String::new(),
            });
        }

        let text = std::fs::read_to_string(path)
            .map_err(|e| JadxError::Io(format!("read {}: {e}", path.display())))?;

        Ok(match kind {
            ResourceType::String => ResourceContent::Strings(parse_strings_xml(&text)),
            ResourceType::Color => ResourceContent::Colors(parse_colors_xml(&text)),
            ResourceType::Dimension => ResourceContent::Dimensions(parse_dimens_xml(&text)),
            ResourceType::Style => ResourceContent::Styles(parse_styles_xml(&text)),
            _ => ResourceContent::Xml(text),
        })
    }
}

const fn update_stats(stats: &mut DecodeStats, res: &DecodedResource) {
    match &res.content {
        ResourceContent::Strings(v) => stats.strings += v.len(),
        ResourceContent::Colors(v) => stats.colors += v.len(),
        ResourceContent::Dimensions(v) => stats.dimensions += v.len(),
        ResourceContent::Styles(v) => stats.styles += v.len(),
        _ => {}
    }
    match &res.kind {
        ResourceType::Layout => stats.layouts += 1,
        ResourceType::Drawable => stats.drawables += 1,
        ResourceType::Asset => stats.assets += 1,
        _ => stats.other += 1,
    }
}

fn sha256_file(_path: &Path) -> String {
    // Placeholder: real implementation would use sha2 crate.
    String::from("(sha256 disabled)")
}

// ─────────────────────────────────────────────────────────────────────────────
// XML parsers (line-oriented, no external XML crate dependency)
// ─────────────────────────────────────────────────────────────────────────────

/// Every `<tag …>…</tag>` occurrence in `text`, wherever it appears.
///
/// The parsers below used to walk `text.lines()` and require the element to
/// start its line. A `strings.xml` with the whole document on one line — which
/// is what a minified or aapt-emitted resource file looks like — then parsed as
/// empty, because the only line began with `<resources>`. Position in the
/// document is not part of the format, so it must not be part of the match.
fn elements<'a>(text: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = text;

    while let Some(start) = rest.find(&open) {
        let after = &rest[start..];
        // `<string` must not match `<stringarray`: the next character has to end
        // the tag name.
        let next = after[open.len()..].chars().next();
        if !matches!(next, Some(c) if c.is_whitespace() || c == '>' || c == '/') {
            rest = &after[open.len()..];
            continue;
        }
        // Take up to the closing tag when there is one, otherwise up to the end
        // of the opening tag so that a self-closing element still yields its
        // attributes.
        let end = after
            .find(&close)
            .map_or_else(|| after.find('>').map_or(after.len(), |g| g + 1), |c| c + close.len());
        out.push(&after[..end]);
        rest = &after[end..];
    }
    out
}

fn parse_strings_xml(text: &str) -> Vec<StringEntry> {
    let mut out = Vec::new();
    for t in elements(text, "string") {
        let name = extract_attr(t, "name").unwrap_or_default();
        let translatable = extract_attr(t, "translatable")
            .is_none_or(|v| v != "false");
        let value = extract_element_value(t).unwrap_or_default();
        if !name.is_empty() {
            out.push(StringEntry { name, value, translatable });
        }
    }
    out
}

fn parse_colors_xml(text: &str) -> Vec<ColorEntry> {
    let mut out = Vec::new();
    for t in elements(text, "color") {
        let name = extract_attr(t, "name").unwrap_or_default();
        let value = extract_element_value(t).unwrap_or_default();
        if name.is_empty() { continue; }
        let argb = parse_color_value(&value);
        out.push(ColorEntry { name, value, argb });
    }
    out
}

fn parse_dimens_xml(text: &str) -> Vec<DimenEntry> {
    let mut out = Vec::new();
    for t in elements(text, "dimen") {
        let name = extract_attr(t, "name").unwrap_or_default();
        let value = extract_element_value(t).unwrap_or_default();
        if name.is_empty() { continue; }
        let (magnitude, unit) = parse_dimen_value(&value);
        out.push(DimenEntry { name, value, magnitude, unit });
    }
    out
}

fn parse_styles_xml(text: &str) -> Vec<StyleEntry> {
    let mut out = Vec::new();
    let mut current: Option<StyleEntry> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("<style") {
            let name = extract_attr(t, "name").unwrap_or_default();
            let parent = extract_attr(t, "parent");
            current = Some(StyleEntry { name, parent, items: Vec::new() });
        } else if t.starts_with("</style") {
            if let Some(s) = current.take() {
                out.push(s);
            }
        } else if t.starts_with("<item")
            && let Some(ref mut s) = current
        {
            let item_name = extract_attr(t, "name").unwrap_or_default();
            let item_value = extract_element_value(t).unwrap_or_default();
            s.items.push((item_name, item_value));
        }
    }
    out
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let pos = tag.find(&needle)?;
    let rest = &tag[pos + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn extract_element_value(tag: &str) -> Option<String> {
    let start = tag.find('>')?;
    let rest = &tag[start + 1..];
    let end = rest.find('<')?;
    Some(rest[..end].to_owned())
}

fn parse_color_value(v: &str) -> Option<u32> {
    let s = v.trim().strip_prefix('#')?;
    match s.len() {
        6 => u32::from_str_radix(&format!("FF{s}"), 16).ok(),
        8 => u32::from_str_radix(s, 16).ok(),
        _ => None,
    }
}

fn parse_dimen_value(v: &str) -> (Option<f64>, Option<String>) {
    let v = v.trim();
    // Find where digits (and '.') end
    let num_end = v
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(v.len());
    let num_str = &v[..num_end];
    let unit_str = v[num_end..].trim().to_owned();
    let magnitude = num_str.parse::<f64>().ok();
    let unit = if unit_str.is_empty() { None } else { Some(unit_str) };
    (magnitude, unit)
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Fast lookup index over a collection of decoded resources.
#[derive(Debug, Default)]
pub struct ResourceIndex {
    resources: Vec<DecodedResource>,
    by_kind: HashMap<String, Vec<usize>>,
    string_map: HashMap<String, String>,
    color_map: HashMap<String, ColorEntry>,
    dimen_map: HashMap<String, DimenEntry>,
}

impl ResourceIndex {
    /// Build an index from a resource list.
    #[must_use]
    pub fn build(resources: Vec<DecodedResource>) -> Self {
        let mut idx = Self {
            resources,
            ..Default::default()
        };
        for (i, res) in idx.resources.iter().enumerate() {
            let kind_key = format!("{:?}", res.kind);
            idx.by_kind.entry(kind_key).or_default().push(i);
            match &res.content {
                ResourceContent::Strings(v) => {
                    for s in v {
                        idx.string_map.insert(s.name.clone(), s.value.clone());
                    }
                }
                ResourceContent::Colors(v) => {
                    for c in v {
                        idx.color_map.insert(c.name.clone(), c.clone());
                    }
                }
                ResourceContent::Dimensions(v) => {
                    for d in v {
                        idx.dimen_map.insert(d.name.clone(), d.clone());
                    }
                }
                _ => {}
            }
        }
        idx
    }

    /// Look up a string resource by name.
    #[must_use]
    pub fn string(&self, name: &str) -> Option<&str> {
        self.string_map.get(name).map(String::as_str)
    }

    /// Look up a color resource by name.
    #[must_use]
    pub fn color(&self, name: &str) -> Option<&ColorEntry> {
        self.color_map.get(name)
    }

    /// Look up a dimension by name.
    #[must_use]
    pub fn dimen(&self, name: &str) -> Option<&DimenEntry> {
        self.dimen_map.get(name)
    }

    /// All string entries (flat).
    pub fn all_strings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.string_map.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// All color entries.
    pub fn all_colors(&self) -> impl Iterator<Item = &ColorEntry> {
        self.color_map.values()
    }

    /// Resources matching a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: &ResourceType) -> Vec<&DecodedResource> {
        let key = format!("{kind:?}");
        self.by_kind
            .get(&key)
            .map(|v| v.iter().map(|&i| &self.resources[i]).collect())
            .unwrap_or_default()
    }

    /// Total resource count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.resources.len()
    }

    /// Returns true if no resources have been indexed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_type_layout() {
        let p = Path::new("res/layout/activity_main.xml");
        assert_eq!(ResourceType::from_path(p), ResourceType::Layout);
    }

    #[test]
    fn test_resource_type_layout_qualified() {
        let p = Path::new("res/layout-land/activity_main.xml");
        assert_eq!(ResourceType::from_path(p), ResourceType::Layout);
    }

    #[test]
    fn test_resource_type_drawable() {
        let p = Path::new("res/drawable/icon.png");
        assert_eq!(ResourceType::from_path(p), ResourceType::Drawable);
    }

    #[test]
    fn test_resource_type_string() {
        let p = Path::new("res/values/strings.xml");
        assert_eq!(ResourceType::from_path(p), ResourceType::String);
    }

    #[test]
    fn test_resource_type_color() {
        let p = Path::new("res/values/colors.xml");
        assert_eq!(ResourceType::from_path(p), ResourceType::Color);
    }

    #[test]
    fn test_resource_type_dimen() {
        let p = Path::new("res/values/dimens.xml");
        assert_eq!(ResourceType::from_path(p), ResourceType::Dimension);
    }

    #[test]
    fn test_resource_type_asset() {
        let p = Path::new("assets/fonts/roboto.ttf");
        assert_eq!(ResourceType::from_path(p), ResourceType::Asset);
    }

    #[test]
    fn test_parse_strings() {
        let xml = r#"<?xml version="1.0"?>
<resources>
    <string name="app_name">My App</string>
    <string name="ok_button" translatable="false">OK</string>
</resources>"#;
        let strings = parse_strings_xml(xml);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].name, "app_name");
        assert_eq!(strings[0].value, "My App");
        assert!(strings[0].translatable);
        assert_eq!(strings[1].name, "ok_button");
        assert!(!strings[1].translatable);
    }

    #[test]
    fn test_parse_colors() {
        let xml = r#"<resources>
    <color name="red">#FF0000</color>
    <color name="alpha_red">#80FF0000</color>
</resources>"#;
        let colors = parse_colors_xml(xml);
        assert_eq!(colors.len(), 2);
        assert_eq!(colors[0].argb, Some(0xFFFF_0000));
        assert_eq!(colors[1].argb, Some(0x80FF_0000));
    }

    #[test]
    fn test_parse_dimens() {
        let xml = r#"<resources>
    <dimen name="margin">16dp</dimen>
    <dimen name="font_size">14sp</dimen>
</resources>"#;
        let dimens = parse_dimens_xml(xml);
        assert_eq!(dimens.len(), 2);
        assert_eq!(dimens[0].magnitude, Some(16.0));
        assert_eq!(dimens[0].unit.as_deref(), Some("dp"));
        assert_eq!(dimens[1].unit.as_deref(), Some("sp"));
    }

    #[test]
    fn test_parse_styles() {
        let xml = r#"<resources>
    <style name="AppTheme" parent="Theme.AppCompat.Light">
        <item name="colorPrimary">@color/primary</item>
        <item name="windowNoTitle">true</item>
    </style>
</resources>"#;
        let styles = parse_styles_xml(xml);
        assert_eq!(styles.len(), 1);
        assert_eq!(styles[0].name, "AppTheme");
        assert_eq!(styles[0].parent.as_deref(), Some("Theme.AppCompat.Light"));
        assert_eq!(styles[0].items.len(), 2);
    }

    #[test]
    fn test_parse_color_value_6digit() {
        assert_eq!(parse_color_value("#FF0000"), Some(0xFFFF_0000));
    }

    #[test]
    fn test_parse_color_value_8digit() {
        assert_eq!(parse_color_value("#AABBCCDD"), Some(0xAABB_CCDD));
    }

    #[test]
    fn test_parse_dimen_dp() {
        let (mag, unit) = parse_dimen_value("8dp");
        assert_eq!(mag, Some(8.0));
        assert_eq!(unit.as_deref(), Some("dp"));
    }

    #[test]
    fn test_resource_index_string() {
        let xml = r#"<resources><string name="hello">Hello World</string></resources>"#;
        let strings = parse_strings_xml(xml);
        let res = DecodedResource {
            kind: ResourceType::String,
            path: PathBuf::from("/tmp/strings.xml"),
            rel_path: PathBuf::from("res/values/strings.xml"),
            content: ResourceContent::Strings(strings),
        };
        let idx = ResourceIndex::build(vec![res]);
        assert_eq!(idx.string("hello"), Some("Hello World"));
        assert_eq!(idx.string("missing"), None);
    }

    #[test]
    fn test_resource_index_color() {
        let xml = r#"<resources><color name="primary">#3F51B5</color></resources>"#;
        let colors = parse_colors_xml(xml);
        let res = DecodedResource {
            kind: ResourceType::Color,
            path: PathBuf::from("/tmp/colors.xml"),
            rel_path: PathBuf::from("res/values/colors.xml"),
            content: ResourceContent::Colors(colors),
        };
        let idx = ResourceIndex::build(vec![res]);
        let c = idx.color("primary").expect("should find primary color");
        assert!(c.argb.is_some());
    }

    #[test]
    fn test_resource_index_by_kind() {
        let res = DecodedResource {
            kind: ResourceType::Layout,
            path: PathBuf::from("/tmp/main.xml"),
            rel_path: PathBuf::from("res/layout/main.xml"),
            content: ResourceContent::Xml("<LinearLayout/>".into()),
        };
        let idx = ResourceIndex::build(vec![res]);
        let layouts = idx.by_kind(&ResourceType::Layout);
        assert_eq!(layouts.len(), 1);
        let colors = idx.by_kind(&ResourceType::Color);
        assert!(colors.is_empty());
    }

    #[test]
    fn test_decoder_default() {
        let d = JadxResourceDecoder::new();
        assert_eq!(d.max_xml_size, 4 * 1024 * 1024);
        assert!(!d.hash_binaries);
    }
}
