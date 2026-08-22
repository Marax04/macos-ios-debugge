//! OOXML relationship parser.
//!
//! Parses `_rels/*.rels` XML files and the `[Content_Types].xml` document
//! found inside Office Open XML packages (`.docx`, `.xlsx`, `.pptx`).
//!
//! Spec reference: ECMA-376 Part 2, §7.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the OOXML relationship parser.
#[derive(Debug, thiserror::Error)]
pub enum OoxmlError {
    /// XML could not be parsed.
    #[error("xml parse error: {0}")]
    XmlParse(String),
    /// A required attribute was missing.
    #[error("missing attribute: {0}")]
    MissingAttribute(String),
    /// An unexpected or malformed value was encountered.
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

// ─── RelKind ──────────────────────────────────────────────────────────────────

/// The kind of an OOXML relationship, derived from its `Type` URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelKind {
    /// `http://…/officeDocument/2006/relationships/officeDocument`
    OfficeDocument,
    /// `http://…/relationships/extended-properties`
    ExtendedProperties,
    /// `http://…/relationships/core-properties`
    CoreProperties,
    /// `http://…/officeDocument/2006/relationships/worksheet`
    Worksheet,
    /// `http://…/officeDocument/2006/relationships/slide`
    Slide,
    /// `http://…/officeDocument/2006/relationships/slideMaster`
    SlideMaster,
    /// `http://…/officeDocument/2006/relationships/slideLayout`
    SlideLayout,
    /// `http://…/officeDocument/2006/relationships/styles`
    Styles,
    /// `http://…/officeDocument/2006/relationships/theme`
    Theme,
    /// `http://…/officeDocument/2006/relationships/image`
    Image,
    /// `http://…/officeDocument/2006/relationships/hyperlink`
    Hyperlink,
    /// `http://…/officeDocument/2006/relationships/vbaProject`
    VbaProject,
    /// `http://…/officeDocument/2006/relationships/sharedStrings`
    SharedStrings,
    /// `http://…/officeDocument/2006/relationships/calcChain`
    CalcChain,
    /// Any other relationship type — stores the raw URI.
    Other(String),
}

impl RelKind {
    /// Parse a relationship type URI into a [`RelKind`].
    #[must_use]
    pub fn from_type_uri(uri: &str) -> Self {
        // Strip common namespace prefixes for matching
        let tail = uri
            .rsplit('/')
            .next()
            .unwrap_or(uri);

        match tail {
            "officeDocument" => Self::OfficeDocument,
            "extended-properties" => Self::ExtendedProperties,
            "core-properties" => Self::CoreProperties,
            "worksheet" => Self::Worksheet,
            "slide" => Self::Slide,
            "slideMaster" => Self::SlideMaster,
            "slideLayout" => Self::SlideLayout,
            "styles" => Self::Styles,
            "theme" => Self::Theme,
            "image" => Self::Image,
            "hyperlink" => Self::Hyperlink,
            "vbaProject" => Self::VbaProject,
            "sharedStrings" => Self::SharedStrings,
            "calcChain" => Self::CalcChain,
            _ => Self::Other(uri.to_owned()),
        }
    }

    /// Return `true` if this relationship points to a VBA project.
    #[must_use]
    pub const fn is_vba(&self) -> bool {
        matches!(self, Self::VbaProject)
    }

    /// Return `true` if this relationship points to an image.
    #[must_use]
    pub const fn is_image(&self) -> bool {
        matches!(self, Self::Image)
    }

    /// Return `true` if this is an external hyperlink.
    #[must_use]
    pub const fn is_hyperlink(&self) -> bool {
        matches!(self, Self::Hyperlink)
    }
}

impl fmt::Display for RelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OfficeDocument => write!(f, "officeDocument"),
            Self::ExtendedProperties => write!(f, "extended-properties"),
            Self::CoreProperties => write!(f, "core-properties"),
            Self::Worksheet => write!(f, "worksheet"),
            Self::Slide => write!(f, "slide"),
            Self::SlideMaster => write!(f, "slideMaster"),
            Self::SlideLayout => write!(f, "slideLayout"),
            Self::Styles => write!(f, "styles"),
            Self::Theme => write!(f, "theme"),
            Self::Image => write!(f, "image"),
            Self::Hyperlink => write!(f, "hyperlink"),
            Self::VbaProject => write!(f, "vbaProject"),
            Self::SharedStrings => write!(f, "sharedStrings"),
            Self::CalcChain => write!(f, "calcChain"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── TargetMode ───────────────────────────────────────────────────────────────

/// Whether a relationship target is internal (within the package) or external.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetMode {
    /// The target is a part within the package.
    Internal,
    /// The target is an external URI.
    External,
}

impl fmt::Display for TargetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal => write!(f, "Internal"),
            Self::External => write!(f, "External"),
        }
    }
}

// ─── Relationship ─────────────────────────────────────────────────────────────

/// A single OOXML relationship entry parsed from a `.rels` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    /// Relationship identifier (e.g. `"rId1"`).
    pub id: String,
    /// Parsed relationship kind.
    pub kind: RelKind,
    /// Raw type URI.
    pub type_uri: String,
    /// Target path or URL.
    pub target: String,
    /// Whether the target is internal or external.
    pub mode: TargetMode,
}

impl Relationship {
    /// Create a new relationship.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        type_uri: impl Into<String>,
        target: impl Into<String>,
        mode: TargetMode,
    ) -> Self {
        let type_uri = type_uri.into();
        let kind = RelKind::from_type_uri(&type_uri);
        Self {
            id: id.into(),
            kind,
            type_uri,
            target: target.into(),
            mode,
        }
    }
}

impl fmt::Display for Relationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Relationship({}, {} -> '{}' [{}])",
            self.id, self.kind, self.target, self.mode
        )
    }
}

// ─── ContentType ──────────────────────────────────────────────────────────────

/// A content-type entry from `[Content_Types].xml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentType {
    /// A default content type for a file extension.
    Default {
        /// File extension (e.g. `"xml"`).
        extension: String,
        /// MIME content type string.
        content_type: String,
    },
    /// An explicit override for a specific part name.
    Override {
        /// Part name (e.g. `/word/document.xml`).
        part_name: String,
        /// MIME content type string.
        content_type: String,
    },
}

impl ContentType {
    /// Return the content type string.
    #[must_use]
    pub const fn content_type_str(&self) -> &str {
        match self {
            Self::Default { content_type, .. } | Self::Override { content_type, .. } => {
                content_type.as_str()
            }
        }
    }

    /// Return `true` if this entry declares a VBA-related part.
    ///
    /// Checks both the MIME content type (`application/vnd.ms-office.vbaProject`,
    /// `ms-vba`) and — for overrides — the part name itself: real-world (and
    /// especially malicious) documents may declare `vbaProject.bin` under an
    /// unrelated content type, so the part name is an independent signal.
    #[must_use]
    pub fn is_vba(&self) -> bool {
        let ct = self.content_type_str();
        if ct.contains("vbaProject") || ct.contains("ms-vba") {
            return true;
        }
        match self {
            Self::Override { part_name, .. } => {
                part_name.to_ascii_lowercase().contains("vbaproject")
            }
            Self::Default { .. } => false,
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default {
                extension,
                content_type,
            } => write!(f, "Default(.{extension} → {content_type})"),
            Self::Override {
                part_name,
                content_type,
            } => write!(f, "Override({part_name} → {content_type})"),
        }
    }
}

// ─── RelationshipSet ─────────────────────────────────────────────────────────

/// A collection of relationships parsed from a single `.rels` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelationshipSet {
    /// All relationships, keyed by their `Id` attribute.
    pub rels: HashMap<String, Relationship>,
    /// The source part name (e.g. `/word/document.xml`).
    pub source_part: String,
}

impl RelationshipSet {
    /// Create an empty relationship set.
    #[must_use]
    pub fn new(source_part: impl Into<String>) -> Self {
        Self {
            rels: HashMap::new(),
            source_part: source_part.into(),
        }
    }

    /// Insert a relationship.
    pub fn insert(&mut self, rel: Relationship) {
        self.rels.insert(rel.id.clone(), rel);
    }

    /// Look up a relationship by its `rId`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Relationship> {
        self.rels.get(id)
    }

    /// Return all relationships of a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: &RelKind) -> Vec<&Relationship> {
        self.rels
            .values()
            .filter(|r| &r.kind == kind)
            .collect()
    }

    /// Return all VBA project relationships.
    #[must_use]
    pub fn vba_projects(&self) -> Vec<&Relationship> {
        self.rels
            .values()
            .filter(|r| r.kind.is_vba())
            .collect()
    }

    /// Return all hyperlink relationships.
    #[must_use]
    pub fn hyperlinks(&self) -> Vec<&Relationship> {
        self.rels
            .values()
            .filter(|r| r.kind.is_hyperlink())
            .collect()
    }

    /// Return the number of relationships.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rels.len()
    }

    /// Return `true` if no relationships are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rels.is_empty()
    }
}

// ─── OoxmlRelParser ───────────────────────────────────────────────────────────

/// Parser for OOXML `.rels` files.
///
/// Implements a minimal XML parser that handles the standard
/// `Relationships` / `Relationship` element structure without requiring
/// an external XML crate.
pub struct OoxmlRelParser;

impl OoxmlRelParser {
    /// Create a new parser instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse the contents of a `.rels` XML file and return a [`RelationshipSet`].
    ///
    /// # Errors
    /// Returns [`OoxmlError::XmlParse`] if the input is structurally invalid.
    pub fn parse(
        &self,
        xml: &str,
        source_part: &str,
    ) -> Result<RelationshipSet, OoxmlError> {
        let mut set = RelationshipSet::new(source_part);

        for element in Self::iter_elements(xml) {
            let element = element.trim();
            if !element.starts_with("Relationship ") && !element.starts_with("Relationship\t") {
                continue;
            }

            let id = Self::attr(element, "Id")
                .ok_or_else(|| OoxmlError::MissingAttribute("Id".into()))?;
            let type_uri = Self::attr(element, "Type")
                .ok_or_else(|| OoxmlError::MissingAttribute("Type".into()))?;
            let target = Self::attr(element, "Target")
                .ok_or_else(|| OoxmlError::MissingAttribute("Target".into()))?;

            let mode_str = Self::attr(element, "TargetMode");
            let mode = match mode_str.as_deref() {
                Some("External") => TargetMode::External,
                _ => TargetMode::Internal,
            };

            let rel = Relationship::new(id, type_uri, target, mode);
            set.insert(rel);
        }

        Ok(set)
    }

    /// Iterate over XML start-tag content (text between `<` and `>`).
    fn iter_elements(xml: &str) -> impl Iterator<Item = &str> {
        xml.split('<')
            .skip(1)
            .filter_map(|chunk| chunk.split('>').next())
    }

    /// Extract a named XML attribute value from an element string.
    ///
    /// Handles both single-quoted and double-quoted values.
    fn attr(element: &str, name: &str) -> Option<String> {
        // Try `name="value"` form
        let search_dq = format!("{name}=\"");
        if let Some(pos) = element.find(&search_dq) {
            let rest = &element[pos + search_dq.len()..];
            return rest.split('"').next().map(str::to_owned);
        }
        // Try `name='value'` form
        let search_sq = format!("{name}='");
        if let Some(pos) = element.find(&search_sq) {
            let rest = &element[pos + search_sq.len()..];
            return rest.split('\'').next().map(str::to_owned);
        }
        None
    }
}

impl Default for OoxmlRelParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── parse_content_types ──────────────────────────────────────────────────────

/// Parse the `[Content_Types].xml` file and return all content type entries.
///
/// # Errors
/// Returns [`OoxmlError::XmlParse`] on malformed input.
pub fn parse_content_types(xml: &str) -> Result<Vec<ContentType>, OoxmlError> {
    let mut out = Vec::new();

    for element in xml.split('<').skip(1).filter_map(|c| c.split('>').next()) {
        let element = element.trim();
        if element.starts_with("Default ") || element.starts_with("Default\t") {
            let ext = extract_attr(element, "Extension")
                .ok_or_else(|| OoxmlError::MissingAttribute("Extension".into()))?;
            let ct = extract_attr(element, "ContentType")
                .ok_or_else(|| OoxmlError::MissingAttribute("ContentType".into()))?;
            out.push(ContentType::Default {
                extension: ext,
                content_type: ct,
            });
        } else if element.starts_with("Override ") || element.starts_with("Override\t") {
            let part = extract_attr(element, "PartName")
                .ok_or_else(|| OoxmlError::MissingAttribute("PartName".into()))?;
            let ct = extract_attr(element, "ContentType")
                .ok_or_else(|| OoxmlError::MissingAttribute("ContentType".into()))?;
            out.push(ContentType::Override {
                part_name: part,
                content_type: ct,
            });
        }
    }

    Ok(out)
}

fn extract_attr(element: &str, name: &str) -> Option<String> {
    let search_dq = format!("{name}=\"");
    if let Some(pos) = element.find(&search_dq) {
        let rest = &element[pos + search_dq.len()..];
        return rest.split('"').next().map(str::to_owned);
    }
    let search_sq = format!("{name}='");
    if let Some(pos) = element.find(&search_sq) {
        let rest = &element[pos + search_sq.len()..];
        return rest.split('\'').next().map(str::to_owned);
    }
    None
}

// ─── RelsDirectory ────────────────────────────────────────────────────────────

/// All `.rels` files parsed from an OOXML package.
#[derive(Debug, Default)]
pub struct RelsDirectory {
    /// Map from `_rels` path to parsed relationship set.
    pub sets: HashMap<String, RelationshipSet>,
    /// Content types.
    pub content_types: Vec<ContentType>,
}

impl RelsDirectory {
    /// Create an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a parsed relationship set.
    pub fn insert(&mut self, path: String, set: RelationshipSet) {
        self.sets.insert(path, set);
    }

    /// Set the content types list.
    pub fn set_content_types(&mut self, types: Vec<ContentType>) {
        self.content_types = types;
    }

    /// Return the root relationship set (`_rels/.rels`), if present.
    #[must_use]
    pub fn root_rels(&self) -> Option<&RelationshipSet> {
        self.sets.get("_rels/.rels")
    }

    /// Return all VBA project relationships found across all `.rels` files.
    #[must_use]
    pub fn all_vba_relationships(&self) -> Vec<&Relationship> {
        self.sets.values().flat_map(|s| s.vba_projects()).collect()
    }

    /// Return all hyperlinks found across all `.rels` files.
    #[must_use]
    pub fn all_hyperlinks(&self) -> Vec<&Relationship> {
        self.sets.values().flat_map(|s| s.hyperlinks()).collect()
    }

    /// Return `true` if any part declares a VBA content type.
    #[must_use]
    pub fn has_vba_content_type(&self) -> bool {
        self.content_types.iter().any(ContentType::is_vba)
    }

    /// Total number of relationships across all sets.
    #[must_use]
    pub fn total_relationship_count(&self) -> usize {
        self.sets.values().map(RelationshipSet::len).sum()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rels_xml() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
    Target="docProps/core.xml"/>
  <Relationship Id="rId3"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
    Target="https://example.com"
    TargetMode="External"/>
  <Relationship Id="rId4"
    Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    Target="word/vbaProject.bin"/>
</Relationships>"#
    }

    fn sample_content_types_xml() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.activeX+xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#
    }

    #[test]
    fn test_rel_kind_from_type_uri_office_document() {
        let k = RelKind::from_type_uri(
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
        );
        assert_eq!(k, RelKind::OfficeDocument);
    }

    #[test]
    fn test_rel_kind_from_type_uri_hyperlink() {
        let k = RelKind::from_type_uri(
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
        );
        assert_eq!(k, RelKind::Hyperlink);
        assert!(k.is_hyperlink());
    }

    #[test]
    fn test_rel_kind_from_type_uri_vba() {
        let k = RelKind::from_type_uri(
            "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
        );
        assert_eq!(k, RelKind::VbaProject);
        assert!(k.is_vba());
    }

    #[test]
    fn test_rel_kind_other() {
        let uri = "http://example.com/custom-relationship";
        let k = RelKind::from_type_uri(uri);
        assert!(matches!(k, RelKind::Other(_)));
    }

    #[test]
    fn test_rel_kind_display() {
        assert_eq!(RelKind::OfficeDocument.to_string(), "officeDocument");
        assert_eq!(RelKind::VbaProject.to_string(), "vbaProject");
        assert_eq!(RelKind::Image.to_string(), "image");
    }

    #[test]
    fn test_target_mode_display() {
        assert_eq!(TargetMode::Internal.to_string(), "Internal");
        assert_eq!(TargetMode::External.to_string(), "External");
    }

    #[test]
    fn test_relationship_new() {
        let rel = Relationship::new(
            "rId1",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
            "word/styles.xml",
            TargetMode::Internal,
        );
        assert_eq!(rel.id, "rId1");
        assert_eq!(rel.kind, RelKind::Styles);
        assert_eq!(rel.target, "word/styles.xml");
        assert_eq!(rel.mode, TargetMode::Internal);
    }

    #[test]
    fn test_relationship_display() {
        let rel = Relationship::new("rId1", "http://ex.com/image", "img.png", TargetMode::Internal);
        let s = rel.to_string();
        assert!(s.contains("rId1"));
        assert!(s.contains("img.png"));
    }

    #[test]
    fn test_ooxml_rel_parser_parse_all_relationships() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        assert_eq!(set.len(), 4);
        assert!(set.get("rId1").is_some());
        assert!(set.get("rId4").is_some());
    }

    #[test]
    fn test_ooxml_rel_parser_source_part() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        assert_eq!(set.source_part, "_rels/.rels");
    }

    #[test]
    fn test_ooxml_rel_parser_office_document() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        let docs = set.by_kind(&RelKind::OfficeDocument);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].target, "word/document.xml");
    }

    #[test]
    fn test_ooxml_rel_parser_hyperlink_external() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        let links = set.hyperlinks();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].mode, TargetMode::External);
        assert_eq!(links[0].target, "https://example.com");
    }

    #[test]
    fn test_ooxml_rel_parser_vba_project() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        let vba = set.vba_projects();
        assert_eq!(vba.len(), 1);
        assert_eq!(vba[0].target, "word/vbaProject.bin");
    }

    #[test]
    fn test_ooxml_rel_parser_empty_xml() {
        let parser = OoxmlRelParser::new();
        let set = parser
            .parse("<Relationships></Relationships>", "_rels/.rels")
            .unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_parse_content_types_defaults() {
        let types = parse_content_types(sample_content_types_xml()).unwrap();
        let defaults: Vec<_> = types
            .iter()
            .filter(|t| matches!(t, ContentType::Default { .. }))
            .collect();
        assert_eq!(defaults.len(), 2);
    }

    #[test]
    fn test_parse_content_types_overrides() {
        let types = parse_content_types(sample_content_types_xml()).unwrap();
        let overrides: Vec<_> = types
            .iter()
            .filter(|t| matches!(t, ContentType::Override { .. }))
            .collect();
        assert_eq!(overrides.len(), 2);
    }

    #[test]
    fn test_parse_content_types_vba_detected() {
        let types = parse_content_types(sample_content_types_xml()).unwrap();
        let has_vba = types.iter().any(super::ContentType::is_vba);
        assert!(has_vba);
    }

    #[test]
    fn test_content_type_display_default() {
        let ct = ContentType::Default {
            extension: "xml".into(),
            content_type: "application/xml".into(),
        };
        let s = ct.to_string();
        assert!(s.contains("xml"));
        assert!(s.contains("application/xml"));
    }

    #[test]
    fn test_content_type_display_override() {
        let ct = ContentType::Override {
            part_name: "/word/document.xml".into(),
            content_type: "application/vnd.openxmlformats".into(),
        };
        let s = ct.to_string();
        assert!(s.contains("/word/document.xml"));
    }

    #[test]
    fn test_rels_directory_root_rels() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        let mut dir = RelsDirectory::new();
        dir.insert("_rels/.rels".into(), set);
        assert!(dir.root_rels().is_some());
        assert_eq!(dir.root_rels().unwrap().len(), 4);
    }

    #[test]
    fn test_rels_directory_all_vba_relationships() {
        let parser = OoxmlRelParser::new();
        let set = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        let mut dir = RelsDirectory::new();
        dir.insert("_rels/.rels".into(), set);
        assert_eq!(dir.all_vba_relationships().len(), 1);
    }

    #[test]
    fn test_rels_directory_total_count() {
        let parser = OoxmlRelParser::new();
        let s1 = parser.parse(sample_rels_xml(), "_rels/.rels").unwrap();
        let s2 = parser
            .parse(
                r#"<Relationships><Relationship Id="rId1" Type="http://a/b/c" Target="x"/></Relationships>"#,
                "word/_rels/document.xml.rels",
            )
            .unwrap();
        let mut dir = RelsDirectory::new();
        dir.insert("_rels/.rels".into(), s1);
        dir.insert("word/_rels/document.xml.rels".into(), s2);
        assert_eq!(dir.total_relationship_count(), 5);
    }

    #[test]
    fn test_rels_directory_has_vba_content_type() {
        let types = parse_content_types(sample_content_types_xml()).unwrap();
        let mut dir = RelsDirectory::new();
        dir.set_content_types(types);
        assert!(dir.has_vba_content_type());
    }

    #[test]
    fn test_rels_directory_no_vba_content_type() {
        let xml = r#"<Types>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>"#;
        let types = parse_content_types(xml).unwrap();
        let mut dir = RelsDirectory::new();
        dir.set_content_types(types);
        assert!(!dir.has_vba_content_type());
    }

    #[test]
    fn test_relationship_set_is_empty() {
        let set = RelationshipSet::new("/");
        assert!(set.is_empty());
    }

    #[test]
    fn test_relationship_set_by_kind_multiple() {
        let mut set = RelationshipSet::new("/");
        set.insert(Relationship::new(
            "rId1",
            "http://a/b/image",
            "img1.png",
            TargetMode::Internal,
        ));
        set.insert(Relationship::new(
            "rId2",
            "http://a/b/image",
            "img2.png",
            TargetMode::Internal,
        ));
        assert_eq!(set.by_kind(&RelKind::Image).len(), 2);
    }

    #[test]
    fn test_ooxml_rel_parser_default_instance() {
        let _ = OoxmlRelParser;
    }
}
