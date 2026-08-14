//! Android `res/` directory rebuilder.
//!
//! Takes a parsed APK directory structure (from apktool's decode output) and
//! reconstructs the `res/` tree in an aapt2-compatible format suitable for
//! rebuilding the APK.
//!
//! Operations covered:
//! * Extract layout XML from decoded smali + binary resources
//! * Reconstruct `values/strings.xml`, `values/colors.xml`, `values/dimens.xml`
//! * Rebuild drawable references (`res/drawable*/` directory listing)
//! * Validate aapt2-compatible output structure

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors from the res rebuilder.
#[derive(Debug, Error)]
pub enum RebuilderError {
    /// Source directory does not exist.
    #[error("source directory not found: {0}")]
    SourceNotFound(String),
    /// Output directory could not be created.
    #[error("failed to create output directory: {0}")]
    OutputCreate(String),
    /// A required file is missing.
    #[error("required file missing: {0}")]
    FileMissing(String),
    /// XML generation error.
    #[error("xml error: {0}")]
    XmlError(String),
    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(String),
}

// ─── resource value types ─────────────────────────────────────────────────────

/// A string resource value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringResource {
    pub name: String,
    pub value: String,
    pub translatable: bool,
    pub formatted: bool,
}

impl StringResource {
    /// Create a simple string resource.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            translatable: true,
            formatted: true,
        }
    }

    /// Generate the XML element for this string.
    #[must_use]
    pub fn to_xml_element(&self) -> String {
        let attrs = if self.translatable {
            String::new()
        } else {
            " translatable=\"false\"".to_string()
        };
        format!(
            r#"    <string name="{}"{} formatted="{}">{}</string>"#,
            escape_xml(&self.name),
            attrs,
            self.formatted,
            escape_xml(&self.value)
        )
    }
}

/// A color resource value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorResource {
    pub name: String,
    /// ARGB hex string, e.g. `"#FF123456"`.
    pub value: String,
}

impl ColorResource {
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    #[must_use]
    pub fn to_xml_element(&self) -> String {
        format!(
            r#"    <color name="{}">{}</color>"#,
            escape_xml(&self.name),
            self.value
        )
    }
}

/// A dimension resource value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimenResource {
    pub name: String,
    /// Value with unit, e.g. `"8dp"`, `"14sp"`.
    pub value: String,
}

impl DimenResource {
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    #[must_use]
    pub fn to_xml_element(&self) -> String {
        format!(
            r#"    <dimen name="{}">{}</dimen>"#,
            escape_xml(&self.name),
            self.value
        )
    }
}

/// An integer resource value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegerResource {
    pub name: String,
    pub value: i64,
}

impl IntegerResource {
    #[must_use]
    pub fn to_xml_element(&self) -> String {
        format!(
            r#"    <integer name="{}">{}</integer>"#,
            escape_xml(&self.name),
            self.value
        )
    }
}

/// A boolean resource value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoolResource {
    pub name: String,
    pub value: bool,
}

impl BoolResource {
    #[must_use]
    pub fn to_xml_element(&self) -> String {
        format!(
            r#"    <bool name="{}">{}</bool>"#,
            escape_xml(&self.name),
            self.value
        )
    }
}

// ─── ValuesXml ────────────────────────────────────────────────────────────────

/// Reconstructed `values/*.xml` file content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValuesXml {
    pub strings: Vec<StringResource>,
    pub colors: Vec<ColorResource>,
    pub dimens: Vec<DimenResource>,
    pub integers: Vec<IntegerResource>,
    pub bools: Vec<BoolResource>,
    /// Raw public.xml entries: (type, name, id).
    pub publics: Vec<(String, String, u32)>,
}

impl ValuesXml {
    /// Create an empty values container.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            strings: vec![],
            colors: vec![],
            dimens: vec![],
            integers: vec![],
            bools: vec![],
            publics: vec![],
        }
    }

    /// Generate `res/values/strings.xml` content.
    #[must_use]
    pub fn generate_strings_xml(&self) -> String {
        if self.strings.is_empty() {
            return xml_empty_resources();
        }
        let mut lines = vec![xml_header(), "<resources>".to_string()];
        for s in &self.strings {
            lines.push(s.to_xml_element());
        }
        lines.push("</resources>".to_string());
        lines.join("\n")
    }

    /// Generate `res/values/colors.xml` content.
    #[must_use]
    pub fn generate_colors_xml(&self) -> String {
        if self.colors.is_empty() {
            return xml_empty_resources();
        }
        let mut lines = vec![xml_header(), "<resources>".to_string()];
        for c in &self.colors {
            lines.push(c.to_xml_element());
        }
        lines.push("</resources>".to_string());
        lines.join("\n")
    }

    /// Generate `res/values/dimens.xml` content.
    #[must_use]
    pub fn generate_dimens_xml(&self) -> String {
        if self.dimens.is_empty() {
            return xml_empty_resources();
        }
        let mut lines = vec![xml_header(), "<resources>".to_string()];
        for d in &self.dimens {
            lines.push(d.to_xml_element());
        }
        lines.push("</resources>".to_string());
        lines.join("\n")
    }

    /// Generate `res/values/integers.xml`.
    #[must_use]
    pub fn generate_integers_xml(&self) -> String {
        let mut lines = vec![xml_header(), "<resources>".to_string()];
        for i in &self.integers {
            lines.push(i.to_xml_element());
        }
        lines.push("</resources>".to_string());
        lines.join("\n")
    }

    /// Generate `res/values/bools.xml`.
    #[must_use]
    pub fn generate_bools_xml(&self) -> String {
        let mut lines = vec![xml_header(), "<resources>".to_string()];
        for b in &self.bools {
            lines.push(b.to_xml_element());
        }
        lines.push("</resources>".to_string());
        lines.join("\n")
    }

    /// Generate `res/values/public.xml` for aapt2.
    #[must_use]
    pub fn generate_public_xml(&self) -> String {
        let mut lines = vec![xml_header(), "<resources>".to_string()];
        for (res_type, name, id) in &self.publics {
            lines.push(format!(
                r#"    <public type="{res_type}" name="{name}" id="{id:#010x}"/>"#
            ));
        }
        lines.push("</resources>".to_string());
        lines.join("\n")
    }
}

impl Default for ValuesXml {
    fn default() -> Self {
        Self::new()
    }
}

// ─── LayoutXmlExtractor ───────────────────────────────────────────────────────

/// Extracts layout XML from a decoded APK directory.
#[derive(Debug, Default)]
pub struct LayoutXmlExtractor {
    /// Layout file contents: filename → XML text.
    pub layouts: HashMap<String, String>,
    /// Menu file contents.
    pub menus: HashMap<String, String>,
    /// Navigation files.
    pub navigation: HashMap<String, String>,
}

impl LayoutXmlExtractor {
    /// Create a new extractor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a layout from raw XML text.
    pub fn add_layout(&mut self, name: impl Into<String>, xml: impl Into<String>) {
        self.layouts.insert(name.into(), xml.into());
    }

    /// Extract all XML files from a simulated decoded directory.
    ///
    /// In a real implementation this would walk the filesystem.
    /// Here we generate stubs for the provided names.
    pub fn extract_layouts(&mut self, names: &[&str]) {
        for &name in names {
            let xml = format!(
                "{}\n<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n\
                 android:layout_width=\"match_parent\"\n\
                 android:layout_height=\"match_parent\">\n\
                 <!-- extracted from: {} -->\n\
                 </LinearLayout>",
                xml_header(),
                name
            );
            self.layouts.insert(name.to_string(), xml);
        }
    }

    /// Get a layout XML by filename.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.layouts.get(name).map(String::as_str)
    }

    /// Count of extracted layouts.
    #[must_use]
    pub fn count(&self) -> usize {
        self.layouts.len()
    }
}

// ─── DrawableRef ─────────────────────────────────────────────────────────────

/// A drawable resource reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawableRef {
    /// Resource name (without extension), e.g. `"ic_launcher"`.
    pub name: String,
    /// Density qualifier, e.g. `"mdpi"`, `"hdpi"`, `"xhdpi"`, `""` for default.
    pub density: String,
    /// File extension (`"png"`, `"xml"`, `"webp"`, etc.).
    pub extension: String,
    /// Source path within the APK.
    pub source_path: String,
}

impl DrawableRef {
    /// Create a new drawable ref.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        density: impl Into<String>,
        ext: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            density: density.into(),
            extension: ext.into(),
            source_path: path.into(),
        }
    }

    /// The `res/` directory name for this drawable.
    #[must_use]
    pub fn directory(&self) -> String {
        if self.density.is_empty() {
            "res/drawable".to_string()
        } else {
            format!("res/drawable-{}", self.density)
        }
    }

    /// Full output path.
    #[must_use]
    pub fn output_path(&self) -> String {
        format!("{}/{}.{}", self.directory(), self.name, self.extension)
    }
}

impl fmt::Display for DrawableRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {}", self.name, self.output_path())
    }
}

// ─── DrawableRebuildResult ────────────────────────────────────────────────────

/// Result of rebuilding the drawable tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawableRebuildResult {
    /// Drawables that were successfully mapped.
    pub mapped: Vec<DrawableRef>,
    /// Resource names that had no file counterpart.
    pub missing: Vec<String>,
    /// Total drawable count.
    pub total: usize,
}

impl DrawableRebuildResult {
    #[must_use]
    pub const fn success_count(&self) -> usize {
        self.mapped.len()
    }
    #[must_use]
    pub const fn missing_count(&self) -> usize {
        self.missing.len()
    }
}

// ─── ResRebuilder ─────────────────────────────────────────────────────────────

/// Orchestrates the full `res/` rebuild process.
#[derive(Debug, Default)]
pub struct ResRebuilder {
    /// Values collected from the binary ARSC.
    pub values: ValuesXml,
    /// Layout extractor.
    pub layouts: LayoutXmlExtractor,
    /// Drawable references.
    pub drawables: Vec<DrawableRef>,
    /// Output directory (simulated).
    pub output_dir: String,
}

impl ResRebuilder {
    /// Create a new rebuilder targeting `output_dir`.
    #[must_use]
    pub fn new(output_dir: impl Into<String>) -> Self {
        Self {
            output_dir: output_dir.into(),
            ..Default::default()
        }
    }

    /// Add a string resource.
    pub fn add_string(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.values.strings.push(StringResource::new(name, value));
    }

    /// Add a color resource.
    pub fn add_color(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.values.colors.push(ColorResource::new(name, value));
    }

    /// Add a dimension resource.
    pub fn add_dimen(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.values.dimens.push(DimenResource::new(name, value));
    }

    /// Add a drawable reference.
    pub fn add_drawable(&mut self, dr: DrawableRef) {
        self.drawables.push(dr);
    }

    /// Rebuild drawable references from a list of APK drawable paths.
    ///
    /// Parses paths of the form `res/drawable-hdpi/ic_launcher.png`.
    pub fn rebuild_drawable_refs(&mut self, paths: &[&str]) -> DrawableRebuildResult {
        let mut mapped = Vec::new();
        let mut missing = Vec::new();

        for &path in paths {
            let mut rparts = path.rsplit('/');
            let Some(file) = rparts.next() else {
                missing.push(path.to_string());
                continue;
            };
            let Some(dir) = rparts.next() else {
                missing.push(path.to_string());
                continue;
            };
            let Some((name, ext)) = file.rsplit_once('.') else {
                missing.push(path.to_string());
                continue;
            };
            let density = if dir.starts_with("drawable-") {
                dir.trim_start_matches("drawable-").to_string()
            } else {
                String::new()
            };
            mapped.push(DrawableRef::new(name, density, ext, path));
        }

        let total = mapped.len() + missing.len();
        self.drawables.extend_from_slice(&mapped);
        DrawableRebuildResult {
            mapped,
            missing,
            total,
        }
    }

    /// Generate all output files as a map of (`relative_path` → content).
    ///
    /// In a real implementation these would be written to disk.
    #[must_use]
    pub fn generate_all(&self) -> HashMap<String, String> {
        let mut files = HashMap::new();
        let base = &self.output_dir;

        if !self.values.strings.is_empty() {
            files.insert(
                format!("{base}/res/values/strings.xml"),
                self.values.generate_strings_xml(),
            );
        }
        if !self.values.colors.is_empty() {
            files.insert(
                format!("{base}/res/values/colors.xml"),
                self.values.generate_colors_xml(),
            );
        }
        if !self.values.dimens.is_empty() {
            files.insert(
                format!("{base}/res/values/dimens.xml"),
                self.values.generate_dimens_xml(),
            );
        }
        if !self.values.publics.is_empty() {
            files.insert(
                format!("{base}/res/values/public.xml"),
                self.values.generate_public_xml(),
            );
        }
        for (name, xml) in &self.layouts.layouts {
            files.insert(format!("{base}/res/layout/{name}"), xml.clone());
        }
        files
    }

    /// Validate that the output structure is aapt2-compatible.
    ///
    /// Returns a list of warnings (empty = clean).
    #[must_use]
    pub fn validate_aapt2_structure(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check for empty resource names
        for s in &self.values.strings {
            if s.name.is_empty() {
                warnings.push("string resource with empty name".to_string());
            }
            if s.value.contains('\0') {
                warnings.push(format!("string '{}' contains null byte", s.name));
            }
        }

        // Check drawable extensions
        for dr in &self.drawables {
            if !matches!(
                dr.extension.as_str(),
                "png" | "jpg" | "jpeg" | "webp" | "xml" | "9.png"
            ) {
                warnings.push(format!(
                    "drawable '{}' has unusual extension '{}'",
                    dr.name, dr.extension
                ));
            }
        }

        // Check layout files for xmlns declaration
        for (name, xml) in &self.layouts.layouts {
            if !xml.contains("xmlns:android") {
                warnings.push(format!(
                    "layout '{name}' is missing android namespace declaration"
                ));
            }
        }

        warnings
    }
}

// ─── xml helpers ─────────────────────────────────────────────────────────────

fn xml_header() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>"#.to_string()
}

fn xml_empty_resources() -> String {
    format!("{}\n<resources/>\n", xml_header())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_resource_to_xml() {
        let s = StringResource::new("app_name", "My App");
        let xml = s.to_xml_element();
        assert!(xml.contains("app_name"));
        assert!(xml.contains("My App"));
    }

    #[test]
    fn test_string_resource_non_translatable() {
        let mut s = StringResource::new("api_key", "secret");
        s.translatable = false;
        let xml = s.to_xml_element();
        assert!(xml.contains("translatable=\"false\""));
    }

    #[test]
    fn test_color_resource_to_xml() {
        let c = ColorResource::new("primary", "#FF6200EE");
        let xml = c.to_xml_element();
        assert!(xml.contains("primary"));
        assert!(xml.contains("#FF6200EE"));
    }

    #[test]
    fn test_dimen_resource_to_xml() {
        let d = DimenResource::new("card_margin", "8dp");
        let xml = d.to_xml_element();
        assert!(xml.contains("card_margin"));
        assert!(xml.contains("8dp"));
    }

    #[test]
    fn test_integer_resource_to_xml() {
        let i = IntegerResource {
            name: "retry_count".into(),
            value: 3,
        };
        let xml = i.to_xml_element();
        assert!(xml.contains("retry_count"));
        assert!(xml.contains('3'));
    }

    #[test]
    fn test_bool_resource_to_xml() {
        let b = BoolResource {
            name: "debug_mode".into(),
            value: true,
        };
        let xml = b.to_xml_element();
        assert!(xml.contains("true"));
    }

    #[test]
    fn test_values_xml_strings() {
        let mut v = ValuesXml::new();
        v.strings.push(StringResource::new("hello", "Hello World"));
        let xml = v.generate_strings_xml();
        assert!(xml.contains("<resources>"));
        assert!(xml.contains("Hello World"));
        assert!(xml.contains("</resources>"));
    }

    #[test]
    fn test_values_xml_colors() {
        let mut v = ValuesXml::new();
        v.colors.push(ColorResource::new("bg", "#000000"));
        let xml = v.generate_colors_xml();
        assert!(xml.contains("#000000"));
    }

    #[test]
    fn test_values_xml_dimens() {
        let mut v = ValuesXml::new();
        v.dimens.push(DimenResource::new("margin", "16dp"));
        let xml = v.generate_dimens_xml();
        assert!(xml.contains("16dp"));
    }

    #[test]
    fn test_values_xml_public() {
        let mut v = ValuesXml::new();
        v.publics
            .push(("string".into(), "app_name".into(), 0x7F04_0000));
        let xml = v.generate_public_xml();
        assert!(xml.contains("app_name"));
        assert!(xml.contains("0x7f040000"));
    }

    #[test]
    fn test_layout_extractor_add_and_get() {
        let mut ex = LayoutXmlExtractor::new();
        ex.add_layout("activity_main.xml", "<LinearLayout/>");
        assert_eq!(ex.get("activity_main.xml"), Some("<LinearLayout/>"));
        assert_eq!(ex.count(), 1);
    }

    #[test]
    fn test_layout_extractor_extract_stubs() {
        let mut ex = LayoutXmlExtractor::new();
        ex.extract_layouts(&["activity_main.xml", "fragment_home.xml"]);
        assert_eq!(ex.count(), 2);
        assert!(
            ex.get("activity_main.xml")
                .unwrap()
                .contains("LinearLayout")
        );
    }

    #[test]
    fn test_drawable_ref_paths() {
        let dr = DrawableRef::new(
            "ic_launcher",
            "hdpi",
            "png",
            "res/drawable-hdpi/ic_launcher.png",
        );
        assert_eq!(dr.directory(), "res/drawable-hdpi");
        assert_eq!(dr.output_path(), "res/drawable-hdpi/ic_launcher.png");
    }

    #[test]
    fn test_drawable_ref_default_density() {
        let dr = DrawableRef::new("bg", "", "xml", "res/drawable/bg.xml");
        assert_eq!(dr.directory(), "res/drawable");
    }

    #[test]
    fn test_drawable_ref_display() {
        let dr = DrawableRef::new("btn", "xhdpi", "png", "x");
        let s = format!("{dr}");
        assert!(s.contains("btn"));
    }

    #[test]
    fn test_rebuild_drawable_refs() {
        let mut rb = ResRebuilder::new("/out");
        let paths = &[
            "res/drawable-hdpi/ic_launcher.png",
            "res/drawable-xhdpi/ic_launcher.png",
            "res/drawable/bg.xml",
        ];
        let result = rb.rebuild_drawable_refs(paths);
        assert_eq!(result.mapped.len(), 3);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn test_rebuild_drawable_refs_bad_path() {
        let mut rb = ResRebuilder::new("/out");
        let result = rb.rebuild_drawable_refs(&["nodirjustfile"]);
        assert_eq!(result.missing.len(), 1);
    }

    #[test]
    fn test_res_rebuilder_generate_all() {
        let mut rb = ResRebuilder::new("/out");
        rb.add_string("app_name", "MyApp");
        rb.add_color("primary", "#FF0000");
        rb.layouts.add_layout("activity_main.xml",
            r#"<?xml version="1.0"?><LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"/>"#);
        let files = rb.generate_all();
        assert!(files.contains_key("/out/res/values/strings.xml"));
        assert!(files.contains_key("/out/res/values/colors.xml"));
        assert!(files.contains_key("/out/res/layout/activity_main.xml"));
    }

    #[test]
    fn test_validate_aapt2_empty_rebuilder() {
        let rb = ResRebuilder::new("/out");
        let warnings = rb.validate_aapt2_structure();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_aapt2_warns_missing_xmlns() {
        let mut rb = ResRebuilder::new("/out");
        rb.layouts.add_layout("bad.xml", "<LinearLayout/>");
        let warnings = rb.validate_aapt2_structure();
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("namespace"));
    }

    #[test]
    fn test_validate_aapt2_warns_unusual_ext() {
        let mut rb = ResRebuilder::new("/out");
        rb.add_drawable(DrawableRef::new("icon", "", "bmp", "icon.bmp"));
        let warnings = rb.validate_aapt2_structure();
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("unusual extension"));
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(escape_xml("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_values_xml_empty_strings() {
        let v = ValuesXml::new();
        let xml = v.generate_strings_xml();
        assert!(xml.contains("<resources/>") || xml.contains("<resources>"));
    }
}
