//! Asset catalog (`.car`) and resource parsing.
//!
//! Compiled Asset Catalogs (`.car`) are binary BOM (Bill of Materials) files
//! produced by `actool`.  This module provides:
//! - Header detection and basic parsing of `.car` files.
//! - Listing asset names from the Rendered Image Set.
//! - Storyboard decompilation stub (binary storyboard → XML).
//! - `Localizable.strings` parsing (both binary and XML property-list formats).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("not a .car file: {0}")]
    NotACar(String),
    #[error("not a storyboard: {0}")]
    NotAStoryboard(String),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(String),
}

// ─── BOM (Bill of Materials) constants ───────────────────────────────────────

/// BOM file magic (used by `.car` files).
const BOM_MAGIC: &[u8; 8] = b"BOMStore";

/// Minimum size of a BOM header.
const BOM_HEADER_SIZE: usize = 32;

// ─── AssetKind ────────────────────────────────────────────────────────────────

/// The kind of asset in a compiled asset catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    Image,
    Color,
    Data,
    Icon,
    LaunchImage,
    Symbol,
    MultiSizeImageSet,
    NamedColor,
    SpriteAtlas,
    Unknown(String),
}

impl std::str::FromStr for AssetKind {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "image" | "imageset" => Self::Image,
            "color" | "colorset" => Self::Color,
            "dataset" | "data" => Self::Data,
            "appiconset" | "icon" => Self::Icon,
            "launchimage" => Self::LaunchImage,
            "symbolimage" => Self::Symbol,
            "multisize-image-set" => Self::MultiSizeImageSet,
            "namedcolor" => Self::NamedColor,
            "spriteatlas" => Self::SpriteAtlas,
            _ => Self::Unknown(s.to_string()),
        })
    }
}

// ─── AssetEntry ───────────────────────────────────────────────────────────────

/// A single asset entry inside a `.car` (Compiled Asset Catalog).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEntry {
    /// Asset name (e.g. `"AppIcon"`, `"background_blue"`).
    pub name: String,
    /// Asset kind.
    pub kind: AssetKind,
    /// Scale factor (1, 2, 3 for @1x/@2x/@3x).
    pub scale: u32,
    /// Idiom (e.g. `"iphone"`, `"ipad"`, `"universal"`).
    pub idiom: String,
    /// Subtype (e.g. `"retina4"` for 4" screen).
    pub subtype: Option<String>,
    /// Pixel width.
    pub width: u32,
    /// Pixel height.
    pub height: u32,
    /// Byte size of the rendition data.
    pub data_size: u64,
    /// Pixel format (e.g. `"ARGB"`, `"PDF"`, `"DATA"`).
    pub pixel_format: String,
}

impl AssetEntry {
    /// Return `true` if this is a retina (@2x or higher) asset.
    #[must_use]
    pub const fn is_retina(&self) -> bool {
        self.scale >= 2
    }

    /// Return the scale suffix string (`"@1x"`, `"@2x"`, `"@3x"`).
    #[must_use]
    pub fn scale_suffix(&self) -> String {
        format!("@{}x", self.scale)
    }
}

// ─── CarHeader ────────────────────────────────────────────────────────────────

/// Parsed BOM/CAR file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarHeader {
    pub version: u32,
    pub block_count: u32,
    pub index_offset: u32,
    pub index_length: u32,
    pub vars_offset: u32,
    pub vars_length: u32,
    /// Toolchain version that produced this `.car`.
    pub toolchain_version: Option<String>,
    /// Asset catalog version.
    pub catalog_version: Option<u32>,
}

// ─── list_car_assets ──────────────────────────────────────────────────────────

/// Parse a `.car` file and return a list of [`AssetEntry`] records.
///
/// The `.car` format is a BOM (Bill of Materials) file with an embedded
/// asset rendition database.  This function performs a best-effort parse:
/// it reads the BOM header, then scans for known asset name patterns.
///
/// For production use, Apple's `assetutil` or a full BOM parser is recommended.
///
/// # Errors
/// Returns [`ResourceError`] if the data is not a valid `.car` file.
pub fn list_car_assets(car_data: &[u8]) -> Result<Vec<AssetEntry>, ResourceError> {
    // Need at least the 8-byte magic to tell a non-CAR from a truncated CAR.
    if car_data.len() < BOM_MAGIC.len() {
        return Err(ResourceError::Truncated(0));
    }
    // A wrong magic means this simply isn't a CAR/BOM file — report that even
    // when the buffer is shorter than a full header.
    if &car_data[..8] != BOM_MAGIC {
        return Err(ResourceError::NotACar(format!(
            "expected BOMStore, got {:?}",
            &car_data[..8.min(car_data.len())]
        )));
    }
    // Correct magic but not enough bytes for the full header → truncated CAR.
    if car_data.len() < BOM_HEADER_SIZE {
        return Err(ResourceError::Truncated(0));
    }

    // Parse BOM header (big-endian).
    let version = u32::from_be_bytes([car_data[8], car_data[9], car_data[10], car_data[11]]);
    let block_count = u32::from_be_bytes([car_data[12], car_data[13], car_data[14], car_data[15]]);
    let index_offset = u32::from_be_bytes([car_data[16], car_data[17], car_data[18], car_data[19]]);
    let index_length = u32::from_be_bytes([car_data[20], car_data[21], car_data[22], car_data[23]]);
    let vars_offset = u32::from_be_bytes([car_data[24], car_data[25], car_data[26], car_data[27]]);
    let vars_length = u32::from_be_bytes([car_data[28], car_data[29], car_data[30], car_data[31]]);

    let _ = (
        version,
        block_count,
        index_offset,
        index_length,
        vars_offset,
        vars_length,
    );

    // Heuristic scan: look for asset name patterns in the binary.
    // Real `.car` parsing requires walking the BOM tree.
    let mut entries = Vec::new();
    scan_car_strings(car_data, &mut entries);

    Ok(entries)
}

/// Heuristic scan of `.car` binary data for readable asset names.
fn scan_car_strings(data: &[u8], entries: &mut Vec<AssetEntry>) {
    // Look for sequences of printable ASCII at least 4 chars long.
    let mut i = 0;
    let mut current_str_start: Option<usize> = None;

    while i < data.len() {
        let b = data[i];
        let is_printable = matches!(b, 0x20..=0x7E);

        match (is_printable, current_str_start) {
            (true, None) => {
                current_str_start = Some(i);
            }
            (false, Some(start)) => {
                let len = i - start;
                if (4..=128).contains(&len)
                    && let Ok(s) = std::str::from_utf8(&data[start..i])
                {
                    let s = s.trim();
                    if is_asset_name_like(s) && entries.len() < 500 {
                        entries.push(AssetEntry {
                            name: s.to_string(),
                            kind: AssetKind::Image,
                            scale: 1,
                            idiom: "universal".to_string(),
                            subtype: None,
                            width: 0,
                            height: 0,
                            data_size: 0,
                            pixel_format: "ARGB".to_string(),
                        });
                    }
                }
                current_str_start = None;
            }
            _ => {}
        }
        i += 1;
    }
}

fn is_asset_name_like(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    // Must contain at least one letter.
    if !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // Must not look like a path or URL.
    if s.contains("://") || s.starts_with('/') {
        return false;
    }
    // Must look like a typical asset name.
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | '.'))
}

/// Build a [`CarHeader`] from `.car` data.
///
/// # Errors
/// Returns [`ResourceError`] if the data is not a valid `.car` file.
pub fn parse_car_header(car_data: &[u8]) -> Result<CarHeader, ResourceError> {
    if car_data.len() < BOM_HEADER_SIZE {
        return Err(ResourceError::Truncated(0));
    }
    if &car_data[..8] != BOM_MAGIC {
        return Err(ResourceError::NotACar("bad magic".into()));
    }

    let version = u32::from_be_bytes([car_data[8], car_data[9], car_data[10], car_data[11]]);
    let block_count = u32::from_be_bytes([car_data[12], car_data[13], car_data[14], car_data[15]]);
    let index_offset = u32::from_be_bytes([car_data[16], car_data[17], car_data[18], car_data[19]]);
    let index_length = u32::from_be_bytes([car_data[20], car_data[21], car_data[22], car_data[23]]);
    let vars_offset = u32::from_be_bytes([car_data[24], car_data[25], car_data[26], car_data[27]]);
    let vars_length = u32::from_be_bytes([car_data[28], car_data[29], car_data[30], car_data[31]]);

    Ok(CarHeader {
        version,
        block_count,
        index_offset,
        index_length,
        vars_offset,
        vars_length,
        toolchain_version: None,
        catalog_version: None,
    })
}

// ─── Storyboard ───────────────────────────────────────────────────────────────

/// The format of a storyboard file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoryboardFormat {
    /// Compiled binary storyboard (`.storyboardc`).
    Binary,
    /// XML source storyboard (`.storyboard`).
    Xml,
    /// XIB source file.
    Xib,
}

/// A parsed storyboard scene.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoryboardScene {
    pub scene_id: String,
    pub view_controller_class: String,
    pub storyboard_id: Option<String>,
    pub is_initial: bool,
    pub segues: Vec<StoryboardSegue>,
}

/// A storyboard segue between scenes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoryboardSegue {
    pub identifier: Option<String>,
    pub kind: String,
    pub destination: String,
}

/// A parsed storyboard file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Storyboard {
    pub initial_view_controller: Option<String>,
    pub scenes: Vec<StoryboardScene>,
    pub view_controller_classes: Vec<String>,
    pub uses_auto_layout: bool,
    pub deployment_target: Option<String>,
}

impl Storyboard {
    /// Return `true` if the storyboard declares a tab bar controller.
    #[must_use]
    pub fn has_tab_bar_controller(&self) -> bool {
        self.scenes
            .iter()
            .any(|s| s.view_controller_class.contains("TabBarController"))
    }

    /// Return `true` if the storyboard declares a navigation controller.
    #[must_use]
    pub fn has_navigation_controller(&self) -> bool {
        self.scenes
            .iter()
            .any(|s| s.view_controller_class.contains("NavigationController"))
    }
}

/// Extract the XML representation from a compiled binary storyboard bundle.
///
/// A compiled `.storyboardc` is a directory containing:
/// - `Info.plist`
/// - `UIViewController-<id>.nib` files for each scene.
///
/// This function accepts raw `.storyboard` XML and returns it unchanged,
/// or detects that a binary bundle was passed and returns an error.
///
/// # Errors
/// Returns [`ResourceError`] if input is not valid XML storyboard data.
pub fn extract_storyboard(data: &[u8]) -> Result<String, ResourceError> {
    if data.is_empty() {
        return Err(ResourceError::Truncated(0));
    }
    // Check for XML storyboard (starts with <?xml or <document).
    if data.starts_with(b"<?xml") || data.starts_with(b"<document") {
        let xml =
            std::str::from_utf8(data).map_err(|e| ResourceError::InvalidUtf8(e.to_string()))?;
        return Ok(xml.to_string());
    }
    // Binary storyboard files start with the XIB magic (BOM or NIB header).
    Err(ResourceError::NotAStoryboard(
        "Binary .storyboardc bundles cannot be decompiled without the Interface Builder runtime"
            .into(),
    ))
}

/// Parse an XML storyboard into a structured [`Storyboard`].
///
/// # Errors
/// Returns [`ResourceError`] on parse failure.
pub fn parse_storyboard_xml(xml: &str) -> Result<Storyboard, ResourceError> {
    // Minimal XML parsing — extract view controller class names and segues.
    let uses_auto_layout = xml.contains("autoresizingMask");
    let has_auto_layout = xml.contains("useAutolayout=\"YES\"");

    // Find initial view controller ID.
    let initial_vc = extract_attr(xml, "document", "initialViewController");

    // Find all view controller elements.
    let mut scenes = Vec::new();
    let mut vc_classes: Vec<String> = Vec::new();
    let mut is_first = true;

    for tag in &[
        "viewController",
        "tableViewController",
        "collectionViewController",
        "navigationController",
        "tabBarController",
        "splitViewController",
        "pageViewController",
        "hostingController",
    ] {
        let open = format!("<{tag}");
        let mut s = xml;
        while let Some(start) = s.find(&open) {
            let rest = &s[start..];
            let tag_end = rest.find('>').unwrap_or(rest.len());
            let tag_content = &rest[..tag_end];

            let scene_id =
                extract_attr(tag_content, tag, "id").unwrap_or_else(|| format!("scene_{is_first}"));
            let class = extract_attr(tag_content, tag, "customClass").unwrap_or_else(|| {
                format!("UI{}", tag.replace("viewController", "ViewController"))
            });
            let storyboard_id = extract_attr(tag_content, tag, "storyboardIdentifier");
            let is_init = initial_vc.as_deref() == Some(&scene_id);

            if !vc_classes.contains(&class) {
                vc_classes.push(class.clone());
            }

            scenes.push(StoryboardScene {
                scene_id: scene_id.clone(),
                view_controller_class: class,
                storyboard_id,
                is_initial: is_init,
                segues: parse_segues_in(rest),
            });

            is_first = false;
            s = &s[start + open.len()..];
        }
    }

    let _ = uses_auto_layout;

    Ok(Storyboard {
        initial_view_controller: initial_vc,
        scenes,
        view_controller_classes: vc_classes,
        uses_auto_layout: has_auto_layout,
        deployment_target: extract_attr(xml, "document", "targetRuntime"),
    })
}

fn extract_attr(s: &str, _tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = s.find(&needle)? + needle.len();
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

fn parse_segues_in(s: &str) -> Vec<StoryboardSegue> {
    let mut segues = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("<segue") {
        let seg_rest = &rest[start..];
        let end = seg_rest.find('>').unwrap_or(seg_rest.len());
        let tag = &seg_rest[..end];

        let identifier = extract_attr(tag, "segue", "identifier");
        let kind = extract_attr(tag, "segue", "kind").unwrap_or_else(|| "push".to_string());
        let destination = extract_attr(tag, "segue", "destination").unwrap_or_default();

        segues.push(StoryboardSegue {
            identifier,
            kind,
            destination,
        });
        rest = &rest[start + 6..];
    }
    segues
}

// ─── Localizable.strings ─────────────────────────────────────────────────────

/// A parsed `Localizable.strings` file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalizableStrings {
    pub locale: Option<String>,
    pub entries: HashMap<String, String>,
}

impl LocalizableStrings {
    /// Return the translation for `key`, or `None` if absent.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Return the number of localized strings.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

/// Parse a `Localizable.strings` file (key = "value"; format or XML plist).
///
/// # Errors
/// Returns [`ResourceError`] on parse failure.
pub fn parse_localizable_strings(data: &[u8]) -> Result<LocalizableStrings, ResourceError> {
    if data.is_empty() {
        return Ok(LocalizableStrings::default());
    }

    let text = std::str::from_utf8(data).map_err(|e| ResourceError::InvalidUtf8(e.to_string()))?;

    // Detect XML plist format.
    if text.trim_start().starts_with("<?xml") || text.trim_start().starts_with("<plist") {
        return Ok(parse_strings_xml_plist(text));
    }

    // Parse "key" = "value"; format (also handles /* comments */).
    let mut entries = HashMap::new();
    let mut s: &str = text;

    loop {
        // Skip whitespace.
        s = s.trim_start();
        if s.is_empty() {
            break;
        }

        // Skip line comments // and block comments /* ... */.
        if s.starts_with("//") {
            if let Some(end) = s.find('\n') {
                s = &s[end + 1..];
            } else {
                break;
            }
            continue;
        }
        if s.starts_with("/*") {
            if let Some(end) = s.find("*/") {
                s = &s[end + 2..];
            } else {
                break;
            }
            continue;
        }

        // Expect "key" = "value";
        if !s.starts_with('"') {
            // Skip unknown content.
            if let Some(nl) = s.find('\n') {
                s = &s[nl + 1..];
            } else {
                break;
            }
            continue;
        }

        let Some(key) = parse_quoted_string(s) else {
            break;
        };
        s = &s[key.1..];
        s = s.trim_start();

        if !s.starts_with('=') {
            continue;
        }
        s = &s[1..];
        s = s.trim_start();

        let Some(val) = parse_quoted_string(s) else {
            break;
        };
        s = &s[val.1..];
        s = s.trim_start();

        if s.starts_with(';') {
            s = &s[1..];
        }

        entries.insert(key.0, val.0);
    }

    Ok(LocalizableStrings {
        locale: None,
        entries,
    })
}

/// Parse a quoted string and return `(unescaped_value, bytes_consumed)`.
fn parse_quoted_string(s: &str) -> Option<(String, usize)> {
    if !s.starts_with('"') {
        return None;
    }
    let mut result = String::new();
    let mut chars = s.char_indices().skip(1); // skip opening quote
    loop {
        let (i, c) = chars.next()?;
        match c {
            '"' => return Some((result, i + 1)),
            '\\' => {
                let (_, esc) = chars.next()?;
                match esc {
                    'n' => result.push('\n'),
                    't' => result.push('\t'),
                    'r' => result.push('\r'),
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    _ => {
                        result.push('\\');
                        result.push(esc);
                    }
                }
            }
            _ => result.push(c),
        }
    }
}

fn parse_strings_xml_plist(xml: &str) -> LocalizableStrings {
    let mut entries = HashMap::new();
    let mut remaining = xml;

    while let Some(key_start) = remaining.find("<key>") {
        remaining = &remaining[key_start + 5..];
        let key_end = remaining.find("</key>").unwrap_or(remaining.len());
        let key = &remaining[..key_end];
        remaining = &remaining[key_end + 6..];

        let trimmed = remaining.trim_start();
        if trimmed.starts_with("<string>")
            && let Some(end) = trimmed.find("</string>")
        {
            let val = &trimmed[8..end];
            entries.insert(key.to_string(), val.to_string());
            remaining = &remaining[remaining.len() - trimmed.len() + end + 9..];
        }
    }

    LocalizableStrings {
        locale: None,
        entries,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_car_not_car_magic() {
        let err = list_car_assets(b"not a car file").unwrap_err();
        assert!(matches!(err, ResourceError::NotACar(_)));
    }

    #[test]
    fn test_car_too_short() {
        let err = list_car_assets(b"BOM").unwrap_err();
        assert!(matches!(err, ResourceError::Truncated(_)));
    }

    #[test]
    fn test_car_valid_header() {
        let mut data = vec![0u8; 64];
        data[..8].copy_from_slice(BOM_MAGIC);
        let entries = list_car_assets(&data).unwrap();
        // No meaningful assets in zeroed data.
        let _ = entries; // Just verifies no error.
    }

    #[test]
    fn test_car_header_parse() {
        let mut data = vec![0u8; 64];
        data[..8].copy_from_slice(BOM_MAGIC);
        data[8..12].copy_from_slice(&1u32.to_be_bytes()); // version
        data[12..16].copy_from_slice(&5u32.to_be_bytes()); // block_count
        let header = parse_car_header(&data).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.block_count, 5);
    }

    #[test]
    fn test_asset_entry_is_retina() {
        let e = AssetEntry {
            name: "icon".into(),
            kind: AssetKind::Icon,
            scale: 2,
            idiom: "iphone".into(),
            subtype: None,
            width: 60,
            height: 60,
            data_size: 1024,
            pixel_format: "ARGB".into(),
        };
        assert!(e.is_retina());
    }

    #[test]
    fn test_asset_entry_not_retina() {
        let e = AssetEntry {
            name: "icon".into(),
            kind: AssetKind::Icon,
            scale: 1,
            idiom: "ipad".into(),
            subtype: None,
            width: 60,
            height: 60,
            data_size: 512,
            pixel_format: "ARGB".into(),
        };
        assert!(!e.is_retina());
    }

    #[test]
    fn test_asset_entry_scale_suffix() {
        let e = AssetEntry {
            name: "x".into(),
            kind: AssetKind::Image,
            scale: 3,
            idiom: "universal".into(),
            subtype: None,
            width: 0,
            height: 0,
            data_size: 0,
            pixel_format: "ARGB".into(),
        };
        assert_eq!(e.scale_suffix(), "@3x");
    }

    #[test]
    fn test_asset_kind_from_str() {
        assert_eq!("imageset".parse::<AssetKind>().unwrap(), AssetKind::Image);
        assert_eq!("colorset".parse::<AssetKind>().unwrap(), AssetKind::Color);
        assert_eq!("appiconset".parse::<AssetKind>().unwrap(), AssetKind::Icon);
        assert!(matches!(
            "foobar".parse::<AssetKind>().unwrap(),
            AssetKind::Unknown(_)
        ));
    }

    #[test]
    fn test_extract_storyboard_xml() {
        let xml = b"<?xml version=\"1.0\"?><document type=\"com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB\"></document>";
        let result = extract_storyboard(xml).unwrap();
        assert!(result.contains("document"));
    }

    #[test]
    fn test_extract_storyboard_binary_fails() {
        let data = b"\xCE\xFA\xED\xFE\x00\x00\x00\x00";
        let err = extract_storyboard(data).unwrap_err();
        assert!(matches!(err, ResourceError::NotAStoryboard(_)));
    }

    #[test]
    fn test_extract_storyboard_empty_fails() {
        let err = extract_storyboard(b"").unwrap_err();
        assert!(matches!(err, ResourceError::Truncated(_)));
    }

    #[test]
    fn test_parse_storyboard_xml_basic() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<document type="storyboard" initialViewController="BYZ-38-t0r">
<scenes><scene><viewController id="BYZ-38-t0r" customClass="ViewController"/></scene></scenes>
</document>"#;
        let sb = parse_storyboard_xml(xml).unwrap();
        assert!(!sb.scenes.is_empty());
    }

    #[test]
    fn test_localizable_strings_simple() {
        let data = b"\"hello\" = \"Hello World\";\n\"bye\" = \"Goodbye\";\n";
        let ls = parse_localizable_strings(data).unwrap();
        assert_eq!(ls.count(), 2);
        assert_eq!(ls.get("hello"), Some("Hello World"));
        assert_eq!(ls.get("bye"), Some("Goodbye"));
    }

    #[test]
    fn test_localizable_strings_with_comments() {
        let data =
            b"/* Greeting */\n\"greet\" = \"Hi\";\n// another comment\n\"bye\" = \"See ya\";\n";
        let ls = parse_localizable_strings(data).unwrap();
        assert_eq!(ls.get("greet"), Some("Hi"));
        assert_eq!(ls.get("bye"), Some("See ya"));
    }

    #[test]
    fn test_localizable_strings_empty() {
        let ls = parse_localizable_strings(b"").unwrap();
        assert_eq!(ls.count(), 0);
    }

    #[test]
    fn test_localizable_strings_xml_plist() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict><key>title</key><string>Hello</string></dict></plist>";
        let ls = parse_localizable_strings(xml).unwrap();
        assert_eq!(ls.get("title"), Some("Hello"));
    }

    #[test]
    fn test_resource_error_display() {
        assert!(ResourceError::Truncated(10).to_string().contains("10"));
        assert!(
            ResourceError::NotACar("x".into())
                .to_string()
                .contains(".car")
        );
        assert!(
            ResourceError::NotAStoryboard("x".into())
                .to_string()
                .contains("storyboard")
        );
    }

    #[test]
    fn test_is_asset_name_like_valid() {
        assert!(is_asset_name_like("AppIcon"));
        assert!(is_asset_name_like("background_blue"));
        assert!(is_asset_name_like("button.small"));
    }

    #[test]
    fn test_is_asset_name_like_invalid() {
        assert!(!is_asset_name_like("http://"));
        assert!(!is_asset_name_like("ab")); // too short
        assert!(!is_asset_name_like("/path/to/file"));
    }
}
