//! Smali annotation parsing — extract `.annotation` blocks from Smali source
//! text and represent them as structured [`SmaliAnnotation`] values.

use std::collections::HashMap;
use std::fmt;

// ─── AnnotationVisibility ─────────────────────────────────────────────────────

/// Dalvik annotation visibility (mirrors `dalvik.annotation.Annotation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnnotationVisibility {
    /// Visible to all code at runtime.
    Runtime,
    /// Only visible in the compiled class file (not at runtime).
    Build,
    /// Only visible to the system.
    System,
}

impl AnnotationVisibility {
    /// Parse the Smali keyword (`runtime`, `build`, `system`).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "runtime" => Some(Self::Runtime),
            "build" => Some(Self::Build),
            "system" => Some(Self::System),
            _ => None,
        }
    }

    /// Canonical Smali keyword for this visibility.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Build => "build",
            Self::System => "system",
        }
    }
}

impl fmt::Display for AnnotationVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── AnnotationValue ─────────────────────────────────────────────────────────

/// A single annotation element value (mirrors `dalvik.annotation.Annotation`).
#[derive(Debug, Clone, PartialEq)]
pub enum AnnotationValue {
    /// String literal (without quotes).
    Str(String),
    /// Integer literal.
    Int(i64),
    /// Float/double literal.
    Float(f64),
    /// Boolean literal.
    Boolean(bool),
    /// Enum reference: `Lsome/Enum;->VALUE:Lsome/Enum;`.
    Enum { owner: String, value_name: String, descriptor: String },
    /// Type reference, e.g. `Ljava/lang/String;`.
    Type(String),
    /// Method reference, e.g. `Ljava/lang/Object;->toString()V`.
    Method(String),
    /// Field reference, e.g. `Ljava/lang/System;->out:Ljava/io/PrintStream;`.
    Field(String),
    /// Nested annotation.
    Nested(Box<SmaliAnnotation>),
    /// Array of values.
    Array(Vec<Self>),
    /// Null literal.
    Null,
}

impl fmt::Display for AnnotationValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Enum { value_name, .. } => write!(f, ".enum {value_name}"),
            Self::Type(t) => write!(f, "{t}"),
            Self::Method(m) => write!(f, "{m}"),
            Self::Field(fd) => write!(f, "{fd}"),
            Self::Nested(ann) => write!(f, "{ann}"),
            Self::Array(elems) => {
                write!(f, "{{")?;
                for (i, e) in elems.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{e}")?;
                }
                write!(f, "}}")
            }
            Self::Null => write!(f, "null"),
        }
    }
}

// ─── AnnotationElement ───────────────────────────────────────────────────────

/// A key-value pair inside a Smali annotation body.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationElement {
    /// Element name (e.g. `value`, `name`, `description`).
    pub key: String,
    /// Parsed value.
    pub value: AnnotationValue,
}

impl AnnotationElement {
    /// Create a new element.
    #[must_use]
    pub fn new(key: impl Into<String>, value: AnnotationValue) -> Self {
        Self { key: key.into(), value }
    }
}

impl fmt::Display for AnnotationElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.key, self.value)
    }
}

// ─── SmaliAnnotation ─────────────────────────────────────────────────────────

/// A fully-parsed Smali annotation instance.
#[derive(Debug, Clone, PartialEq)]
pub struct SmaliAnnotation {
    /// Visibility keyword (`runtime`, `build`, `system`).
    pub visibility: AnnotationVisibility,
    /// Type descriptor of the annotation class, e.g. `Ljava/lang/Deprecated;`.
    pub annotation_type: String,
    /// Key-value elements inside the annotation body.
    pub elements: Vec<AnnotationElement>,
}

impl SmaliAnnotation {
    /// Create an annotation with no elements.
    #[must_use]
    pub fn new(
        visibility: AnnotationVisibility,
        annotation_type: impl Into<String>,
    ) -> Self {
        Self {
            visibility,
            annotation_type: annotation_type.into(),
            elements: Vec::new(),
        }
    }

    /// Add an element.
    pub fn add_element(&mut self, element: AnnotationElement) {
        self.elements.push(element);
    }

    /// Look up an element by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&AnnotationValue> {
        self.elements.iter().find(|e| e.key == key).map(|e| &e.value)
    }

    /// Returns `true` if the annotation has no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Number of key-value elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns the short class name (last component after `/`, without `L` and `;`).
    #[must_use]
    pub fn short_name(&self) -> &str {
        let inner = self.annotation_type
            .trim_start_matches('L')
            .trim_end_matches(';');
        inner.rsplit('/').next().unwrap_or(inner)
    }

    /// Returns `true` if this annotation matches the given type descriptor.
    #[must_use]
    pub fn is_type(&self, descriptor: &str) -> bool {
        self.annotation_type == descriptor
    }
}

impl fmt::Display for SmaliAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ".annotation {} {}", self.visibility, self.annotation_type)?;
        for elem in &self.elements {
            write!(f, "\n    {elem}")?;
        }
        write!(f, "\n.end annotation")
    }
}

// ─── SmaliAnnotationParser ───────────────────────────────────────────────────

/// Parses `.annotation` blocks from Smali source text.
///
/// Operates line-by-line on the text between `.annotation` and
/// `.end annotation` markers.
pub struct SmaliAnnotationParser;

impl SmaliAnnotationParser {
    /// Create a new parser instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse all annotations from a Smali source string.
    ///
    /// Returns a list of annotations found in the source.
    #[must_use]
    pub fn parse_all(&self, source: &str) -> Vec<SmaliAnnotation> {
        let mut result = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();
            if let Some(ann) = Self::try_parse_annotation_header(line) {
                let (elements, end_idx) = Self::parse_body(&lines, i + 1);
                let mut annotation = ann;
                for elem in elements {
                    annotation.add_element(elem);
                }
                result.push(annotation);
                i = end_idx + 1;
            } else {
                i += 1;
            }
        }
        result
    }

    /// Parse a single annotation starting from `start_line` in a Smali method
    /// or class body.
    ///
    /// Returns the annotation and the line index of `.end annotation`.
    #[must_use]
    pub fn parse_single(&self, lines: &[&str], start_line: usize) -> Option<(SmaliAnnotation, usize)> {
        let header = lines.get(start_line)?.trim();
        let ann = Self::try_parse_annotation_header(header)?;
        let (elements, end_idx) = Self::parse_body(lines, start_line + 1);
        let mut annotation = ann;
        for elem in elements {
            annotation.add_element(elem);
        }
        Some((annotation, end_idx))
    }

    fn try_parse_annotation_header(line: &str) -> Option<SmaliAnnotation> {
        // Format: .annotation <visibility> <type_descriptor>
        if !line.starts_with(".annotation") {
            return None;
        }
        let rest = line.trim_start_matches(".annotation").trim();
        let mut parts = rest.splitn(2, ' ');
        let vis_str = parts.next()?.trim();
        let type_str = parts.next().unwrap_or("").trim();
        let visibility = AnnotationVisibility::from_str(vis_str)?;
        if type_str.is_empty() {
            return None;
        }
        Some(SmaliAnnotation::new(visibility, type_str))
    }

    fn parse_body(lines: &[&str], start: usize) -> (Vec<AnnotationElement>, usize) {
        let mut elements = Vec::new();
        let mut i = start;
        while i < lines.len() {
            let line = lines[i].trim();
            if line == ".end annotation" {
                return (elements, i);
            }
            if let Some(elem) = parse_element_line(line) {
                elements.push(elem);
            }
            i += 1;
        }
        (elements, i.saturating_sub(1))
    }
}

impl Default for SmaliAnnotationParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Element line parser ──────────────────────────────────────────────────────

fn parse_element_line(line: &str) -> Option<AnnotationElement> {
    // Skip sub-annotations and array markers for now
    if line.starts_with('.') || line.is_empty() || line.starts_with('#') {
        return None;
    }
    let eq = line.find('=')?;
    let key = line[..eq].trim().to_string();
    let raw_value = line[eq + 1..].trim();
    let value = parse_value(raw_value);
    Some(AnnotationElement::new(key, value))
}

fn parse_value(s: &str) -> AnnotationValue {
    if s == "null" {
        return AnnotationValue::Null;
    }
    if s == "true" {
        return AnnotationValue::Boolean(true);
    }
    if s == "false" {
        return AnnotationValue::Boolean(false);
    }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = s[1..s.len() - 1].to_string();
        return AnnotationValue::Str(inner);
    }
    if s.starts_with(".enum ") {
        let rest = s.trim_start_matches(".enum ").trim();
        return parse_enum_ref(rest);
    }
    // Type reference
    if s.starts_with('L') && s.ends_with(';') {
        return AnnotationValue::Type(s.to_string());
    }
    // Method reference (contains `->` and `(`)
    if s.contains("->") && s.contains('(') {
        return AnnotationValue::Method(s.to_string());
    }
    // Field reference (contains `->` and `:`)
    if s.contains("->") && s.contains(':') {
        return AnnotationValue::Field(s.to_string());
    }
    // Integer
    if let Ok(n) = s.parse::<i64>() {
        return AnnotationValue::Int(n);
    }
    // Hex integer
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        && let Ok(n) = i64::from_str_radix(hex, 16) {
            return AnnotationValue::Int(n);
        }
    // Float / double
    let float_str = s.trim_end_matches('f').trim_end_matches('F');
    if let Ok(v) = float_str.parse::<f64>() {
        return AnnotationValue::Float(v);
    }
    // Unknown — treat as string
    AnnotationValue::Str(s.to_string())
}

fn parse_enum_ref(s: &str) -> AnnotationValue {
    // Format: Lsome/Enum;->VALUE_NAME:Lsome/Enum;
    if let Some(arrow) = s.find("->") {
        let owner = s[..arrow].to_string();
        let rest = &s[arrow + 2..];
        if let Some(colon) = rest.find(':') {
            let value_name = rest[..colon].to_string();
            let descriptor = rest[colon + 1..].to_string();
            return AnnotationValue::Enum { owner, value_name, descriptor };
        }
    }
    AnnotationValue::Str(s.to_string())
}

// ─── AnnotationIndex ─────────────────────────────────────────────────────────

/// An index of annotations grouped by type descriptor.
#[derive(Debug, Default)]
pub struct AnnotationIndex {
    by_type: HashMap<String, Vec<SmaliAnnotation>>,
}

impl AnnotationIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an annotation into the index.
    pub fn insert(&mut self, annotation: SmaliAnnotation) {
        self.by_type
            .entry(annotation.annotation_type.clone())
            .or_default()
            .push(annotation);
    }

    /// Build an index from a list of annotations.
    #[must_use]
    pub fn from_annotations(annotations: Vec<SmaliAnnotation>) -> Self {
        let mut idx = Self::new();
        for ann in annotations {
            idx.insert(ann);
        }
        idx
    }

    /// Look up all annotations of the given type.
    #[must_use]
    pub fn get(&self, annotation_type: &str) -> &[SmaliAnnotation] {
        self.by_type
            .get(annotation_type)
            .map_or(&[], Vec::as_slice)
    }

    /// Returns `true` if any annotation of the given type is present.
    #[must_use]
    pub fn contains(&self, annotation_type: &str) -> bool {
        self.by_type.contains_key(annotation_type)
    }

    /// All distinct annotation type descriptors in this index.
    #[must_use]
    pub fn types(&self) -> Vec<&str> {
        let mut ts: Vec<&str> = self.by_type.keys().map(String::as_str).collect();
        ts.sort_unstable();
        ts
    }

    /// Total number of annotations in the index.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.by_type.values().map(Vec::len).sum()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> SmaliAnnotationParser {
        SmaliAnnotationParser::new()
    }

    const SIMPLE_SOURCE: &str = r"
.annotation runtime Ljava/lang/Deprecated;
.end annotation
";

    const MULTIKEY_SOURCE: &str = r#"
.annotation runtime Lcom/example/Meta;
    name = "hello"
    version = 42
    debug = true
.end annotation
"#;

    #[test]
    fn test_parse_simple_annotation() {
        let anns = parser().parse_all(SIMPLE_SOURCE);
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].annotation_type, "Ljava/lang/Deprecated;");
        assert_eq!(anns[0].visibility, AnnotationVisibility::Runtime);
    }

    #[test]
    fn test_parse_annotation_with_elements() {
        let anns = parser().parse_all(MULTIKEY_SOURCE);
        assert_eq!(anns.len(), 1);
        let ann = &anns[0];
        assert_eq!(ann.len(), 3);
        assert_eq!(ann.get("name"), Some(&AnnotationValue::Str("hello".to_string())));
        assert_eq!(ann.get("version"), Some(&AnnotationValue::Int(42)));
        assert_eq!(ann.get("debug"), Some(&AnnotationValue::Boolean(true)));
    }

    #[test]
    fn test_short_name() {
        let ann = SmaliAnnotation::new(AnnotationVisibility::Runtime, "Ljava/lang/Deprecated;");
        assert_eq!(ann.short_name(), "Deprecated");
    }

    #[test]
    fn test_is_type() {
        let ann = SmaliAnnotation::new(AnnotationVisibility::Build, "Ldalvik/annotation/Throws;");
        assert!(ann.is_type("Ldalvik/annotation/Throws;"));
        assert!(!ann.is_type("Ljava/lang/Deprecated;"));
    }

    #[test]
    fn test_visibility_parse() {
        assert_eq!(AnnotationVisibility::from_str("runtime"), Some(AnnotationVisibility::Runtime));
        assert_eq!(AnnotationVisibility::from_str("build"), Some(AnnotationVisibility::Build));
        assert_eq!(AnnotationVisibility::from_str("system"), Some(AnnotationVisibility::System));
        assert_eq!(AnnotationVisibility::from_str("unknown"), None);
    }

    #[test]
    fn test_parse_enum_value() {
        let v = parse_value(".enum Landroid/util/Log;->DEBUG:I");
        if let AnnotationValue::Enum { value_name, .. } = v {
            assert_eq!(value_name, "DEBUG");
        } else {
            panic!("expected Enum");
        }
    }

    #[test]
    fn test_parse_null_value() {
        assert_eq!(parse_value("null"), AnnotationValue::Null);
    }

    #[test]
    fn test_annotation_index() {
        let ann1 = SmaliAnnotation::new(AnnotationVisibility::Runtime, "Ljava/lang/Deprecated;");
        let ann2 = SmaliAnnotation::new(AnnotationVisibility::Build, "Ldalvik/annotation/Throws;");
        let ann3 = SmaliAnnotation::new(AnnotationVisibility::Runtime, "Ljava/lang/Deprecated;");
        let idx = AnnotationIndex::from_annotations(vec![ann1, ann2, ann3]);
        assert_eq!(idx.get("Ljava/lang/Deprecated;").len(), 2);
        assert!(idx.contains("Ldalvik/annotation/Throws;"));
        assert_eq!(idx.total_count(), 3);
    }

    #[test]
    fn test_display_annotation() {
        let mut ann = SmaliAnnotation::new(AnnotationVisibility::Runtime, "Ljava/lang/Override;");
        ann.add_element(AnnotationElement::new("x", AnnotationValue::Int(1)));
        let s = ann.to_string();
        assert!(s.contains(".annotation runtime"));
        assert!(s.contains("x = 1"));
        assert!(s.contains(".end annotation"));
    }

    #[test]
    fn test_multiple_annotations_in_source() {
        let src = format!("{SIMPLE_SOURCE}\n{MULTIKEY_SOURCE}");
        let anns = parser().parse_all(&src);
        assert_eq!(anns.len(), 2);
    }

    #[test]
    fn test_annotation_value_display_str() {
        let v = AnnotationValue::Str("hello".to_string());
        assert_eq!(v.to_string(), "\"hello\"");
    }

    #[test]
    fn test_annotation_value_display_array() {
        let v = AnnotationValue::Array(vec![AnnotationValue::Int(1), AnnotationValue::Int(2)]);
        assert!(v.to_string().contains('{'));
    }
}
