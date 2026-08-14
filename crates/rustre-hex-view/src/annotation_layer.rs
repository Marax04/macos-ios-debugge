//! Annotation layer for `rustre-hex-view`.
//!
//! Provides [`AnnotationLayer`] with source-tagged overlays for hex view.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AnnotationSource
// ---------------------------------------------------------------------------

/// The origin of an annotation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnnotationSource {
    User,
    Analysis,
    Template,
    Yara,
    Flirt,
    Script,
    Custom(String),
}

impl fmt::Display for AnnotationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::User => "user",
            Self::Analysis => "analysis",
            Self::Template => "template",
            Self::Yara => "yara",
            Self::Flirt => "flirt",
            Self::Script => "script",
            Self::Custom(n) => n.as_str(),
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Annotation
// ---------------------------------------------------------------------------

/// A single annotation in the hex view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: u64,
    pub offset: u64,
    pub length: usize,
    /// HTML color string, e.g. `#FF0000`.
    pub color: String,
    pub label: String,
    pub tooltip: String,
    pub source: AnnotationSource,
    /// Whether the annotation is visible.
    pub visible: bool,
}

impl Annotation {
    #[must_use]
    pub fn new(
        id: u64,
        offset: u64,
        length: usize,
        label: impl Into<String>,
        source: AnnotationSource,
    ) -> Self {
        Self {
            id,
            offset,
            length,
            color: "#FFFF00".to_string(),
            label: label.into(),
            tooltip: String::new(),
            source,
            visible: true,
        }
    }

    #[must_use]
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.color = color.into();
        self
    }

    #[must_use]
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = tooltip.into();
        self
    }

    /// End offset (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.offset + self.length as u64
    }

    /// Returns `true` if this annotation overlaps with `[start, end)`.
    #[must_use]
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        self.offset < end && self.end() > start
    }
}

impl fmt::Display for Annotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Annotation[{}] ({}) @ {:#x}+{}: {}",
            self.id, self.source, self.offset, self.length, self.label
        )
    }
}

// ---------------------------------------------------------------------------
// AnnotationFilter
// ---------------------------------------------------------------------------

/// Criteria for filtering annotations.
#[derive(Debug, Clone, Default)]
pub struct AnnotationFilter {
    pub source: Option<AnnotationSource>,
    pub visible_only: bool,
    pub min_offset: Option<u64>,
    pub max_offset: Option<u64>,
    pub label_contains: Option<String>,
}

impl AnnotationFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn for_source(mut self, src: AnnotationSource) -> Self {
        self.source = Some(src);
        self
    }

    #[must_use]
    pub const fn visible_only(mut self) -> Self {
        self.visible_only = true;
        self
    }

    #[must_use]
    pub const fn in_range(mut self, start: u64, end: u64) -> Self {
        self.min_offset = Some(start);
        self.max_offset = Some(end);
        self
    }

    #[must_use]
    pub fn label_contains(mut self, s: impl Into<String>) -> Self {
        self.label_contains = Some(s.into());
        self
    }

    #[must_use]
    pub fn matches(&self, ann: &Annotation) -> bool {
        if self.visible_only && !ann.visible {
            return false;
        }
        if let Some(ref src) = self.source && &ann.source != src {
            return false;
        }
        if let (Some(min), Some(max)) = (self.min_offset, self.max_offset) && !ann.overlaps(min, max) {
            return false;
        }
        if let Some(ref s) = self.label_contains && !ann.label.contains(s.as_str()) {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// AnnotationRenderer
// ---------------------------------------------------------------------------

/// Renders annotations as HTML/CSS spans.
#[derive(Debug, Default)]
pub struct AnnotationRenderer;

impl AnnotationRenderer {
    /// Render an annotation as an HTML span element.
    #[must_use]
    pub fn render_html(ann: &Annotation) -> String {
        format!(
            r#"<span class="annotation" style="background-color:{};" title="{}" data-id="{}">{}</span>"#,
            ann.color, ann.tooltip, ann.id, ann.label
        )
    }

    /// Render annotations overlapping a viewport `[start, end)` as a list of spans.
    #[must_use]
    pub fn render_viewport(annotations: &[&Annotation], start: u64, end: u64) -> Vec<String> {
        annotations
            .iter()
            .filter(|a| a.visible && a.overlaps(start, end))
            .map(|a| Self::render_html(a))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AnnotationExport / Import
// ---------------------------------------------------------------------------

/// Exports annotations to JSON.
#[derive(Debug, Default)]
pub struct AnnotationExport;

impl AnnotationExport {
    /// Serialize annotations to a JSON string.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on serialization failure.
    pub fn to_json(annotations: &[Annotation]) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(annotations)
    }

    /// Deserialize annotations from a JSON string.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on deserialization failure.
    pub fn from_json(json: &str) -> Result<Vec<Annotation>, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Imports annotations from external sources.
#[derive(Debug, Default)]
pub struct AnnotationImport;

impl AnnotationImport {
    /// Import YARA match offsets as annotations.
    #[must_use]
    pub fn from_yara_matches(matches: &[(u64, usize, String)], id_start: u64) -> Vec<Annotation> {
        matches
            .iter()
            .enumerate()
            .map(|(i, (off, len, name))| {
                Annotation::new(
                    id_start + i as u64,
                    *off,
                    *len,
                    name.clone(),
                    AnnotationSource::Yara,
                )
                .with_color("#FF8800")
            })
            .collect()
    }

    /// Import template field annotations.
    #[must_use]
    pub fn from_template_fields(fields: &[(u64, usize, String)], id_start: u64) -> Vec<Annotation> {
        fields
            .iter()
            .enumerate()
            .map(|(i, (off, len, name))| {
                Annotation::new(
                    id_start + i as u64,
                    *off,
                    *len,
                    name.clone(),
                    AnnotationSource::Template,
                )
                .with_color("#88FF88")
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AnnotationLayer
// ---------------------------------------------------------------------------

/// The annotation layer manages all annotations for a hex view.
pub struct AnnotationLayer {
    annotations: Vec<Annotation>,
    next_id: u64,
    /// Spatial index: `bucket_index` → annotation ids.
    index: HashMap<u64, Vec<u64>>,
    bucket_size: u64,
}

impl AnnotationLayer {
    /// Create a new annotation layer with the given bucket size for spatial indexing.
    #[must_use]
    pub fn new(bucket_size: u64) -> Self {
        Self {
            annotations: Vec::new(),
            next_id: 1,
            index: HashMap::new(),
            bucket_size: bucket_size.max(1),
        }
    }

    /// Add an annotation and return its assigned ID.
    pub fn add(&mut self, mut ann: Annotation) -> u64 {
        let id = self.next_id;
        ann.id = id;
        self.next_id += 1;
        self.index_annotation(&ann);
        self.annotations.push(ann);
        id
    }

    /// Add a simple user annotation.
    pub fn annotate(
        &mut self,
        offset: u64,
        length: usize,
        label: impl Into<String>,
        color: impl Into<String>,
    ) -> u64 {
        let ann =
            Annotation::new(0, offset, length, label, AnnotationSource::User).with_color(color);
        self.add(ann)
    }

    /// Remove the annotation with the given ID.
    pub fn remove(&mut self, id: u64) {
        if let Some(pos) = self.annotations.iter().position(|a| a.id == id) {
            let ann = self.annotations.remove(pos);
            // Remove from index.
            let bucket = ann.offset / self.bucket_size;
            if let Some(ids) = self.index.get_mut(&bucket) {
                ids.retain(|&v| v != id);
            }
        }
    }

    /// Get the annotation with the given ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Annotation> {
        self.annotations.iter().find(|a| a.id == id)
    }

    /// Get a mutable reference to the annotation with the given ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Annotation> {
        self.annotations.iter_mut().find(|a| a.id == id)
    }

    /// Return all annotations overlapping `[start, end)`, sorted by offset.
    #[must_use]
    pub fn in_range(&self, start: u64, end: u64) -> Vec<&Annotation> {
        let mut results: Vec<&Annotation> = self
            .annotations
            .iter()
            .filter(|a| a.overlaps(start, end))
            .collect();
        results.sort_by_key(|a| a.offset);
        results
    }

    /// Apply a filter and return matching annotations.
    #[must_use]
    pub fn filter(&self, filter: &AnnotationFilter) -> Vec<&Annotation> {
        self.annotations
            .iter()
            .filter(|a| filter.matches(a))
            .collect()
    }

    /// Show all annotations.
    pub fn show_all(&mut self) {
        for a in &mut self.annotations {
            a.visible = true;
        }
    }

    /// Hide all annotations.
    pub fn hide_all(&mut self) {
        for a in &mut self.annotations {
            a.visible = false;
        }
    }

    /// Show annotations from a specific source.
    pub fn show_source(&mut self, source: &AnnotationSource) {
        for a in &mut self.annotations {
            if &a.source == source {
                a.visible = true;
            }
        }
    }

    /// Hide annotations from a specific source.
    pub fn hide_source(&mut self, source: &AnnotationSource) {
        for a in &mut self.annotations {
            if &a.source == source {
                a.visible = false;
            }
        }
    }

    /// Total annotation count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.annotations.len()
    }

    /// Visible annotation count.
    #[must_use]
    pub fn visible_count(&self) -> usize {
        self.annotations.iter().filter(|a| a.visible).count()
    }

    /// Clear all annotations.
    pub fn clear(&mut self) {
        self.annotations.clear();
        self.index.clear();
    }

    /// Export all annotations to JSON.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on serialization failure.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        AnnotationExport::to_json(&self.annotations)
    }

    /// Import annotations from JSON, adding them to the layer.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on deserialization failure.
    pub fn import_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let anns: Vec<Annotation> = AnnotationExport::from_json(json)?;
        let count = anns.len();
        for ann in anns {
            self.add(ann);
        }
        Ok(count)
    }

    fn index_annotation(&mut self, ann: &Annotation) {
        let bucket = ann.offset / self.bucket_size;
        self.index.entry(bucket).or_default().push(ann.id);
    }

    /// Render visible annotations in `[start, end)` as HTML.
    #[must_use]
    pub fn render_html(&self, start: u64, end: u64) -> Vec<String> {
        let visible: Vec<&Annotation> = self
            .in_range(start, end)
            .into_iter()
            .filter(|a| a.visible)
            .collect();
        AnnotationRenderer::render_viewport(&visible, start, end)
    }
}

impl Default for AnnotationLayer {
    fn default() -> Self {
        Self::new(256)
    }
}

impl fmt::Debug for AnnotationLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnnotationLayer({} annotations, {} visible)",
            self.count(),
            self.visible_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layer() -> AnnotationLayer {
        AnnotationLayer::new(256)
    }

    // ── Annotation ────────────────────────────────────────────────────────

    #[test]
    fn annotation_end() {
        let a = Annotation::new(1, 0x1000, 16, "test", AnnotationSource::User);
        assert_eq!(a.end(), 0x1010);
    }

    #[test]
    fn annotation_overlaps() {
        let a = Annotation::new(1, 0x100, 16, "", AnnotationSource::User);
        assert!(a.overlaps(0x108, 0x120));
        assert!(!a.overlaps(0x110, 0x120)); // after end
        assert!(!a.overlaps(0x80, 0x100)); // before start
    }

    #[test]
    fn annotation_display() {
        let a = Annotation::new(1, 0x1000, 4, "magic", AnnotationSource::Template);
        let s = a.to_string();
        assert!(s.contains("magic"));
        assert!(s.contains("template"));
    }

    #[test]
    fn annotation_with_color_and_tooltip() {
        let a = Annotation::new(1, 0, 1, "", AnnotationSource::User)
            .with_color("#00FF00")
            .with_tooltip("My tooltip");
        assert_eq!(a.color, "#00FF00");
        assert_eq!(a.tooltip, "My tooltip");
    }

    // ── AnnotationLayer ───────────────────────────────────────────────────

    #[test]
    fn layer_add_and_count() {
        let mut layer = make_layer();
        let id = layer.annotate(0x1000, 4, "test", "#FF0000");
        assert_eq!(layer.count(), 1);
        assert_eq!(id, 1);
    }

    #[test]
    fn layer_get_by_id() {
        let mut layer = make_layer();
        let id = layer.annotate(0x1000, 4, "x", "#FF0000");
        assert!(layer.get(id).is_some());
        assert!(layer.get(999).is_none());
    }

    #[test]
    fn layer_remove() {
        let mut layer = make_layer();
        let id = layer.annotate(0x1000, 4, "x", "#FF0000");
        layer.remove(id);
        assert_eq!(layer.count(), 0);
    }

    #[test]
    fn layer_in_range() {
        let mut layer = make_layer();
        layer.annotate(0x1000, 4, "a", "#FF0000");
        layer.annotate(0x2000, 4, "b", "#00FF00");
        let results = layer.in_range(0x1000, 0x1010);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "a");
    }

    #[test]
    fn layer_in_range_empty() {
        let layer = make_layer();
        assert!(layer.in_range(0, 0x100).is_empty());
    }

    #[test]
    fn layer_hide_show_all() {
        let mut layer = make_layer();
        layer.annotate(0, 1, "x", "#FF0000");
        layer.hide_all();
        assert_eq!(layer.visible_count(), 0);
        layer.show_all();
        assert_eq!(layer.visible_count(), 1);
    }

    #[test]
    fn layer_hide_source() {
        let mut layer = make_layer();
        layer.annotate(0, 1, "user", "#FF0000");
        let yara_ann = Annotation::new(0, 0x100, 4, "yara_match", AnnotationSource::Yara);
        layer.add(yara_ann);
        layer.hide_source(&AnnotationSource::Yara);
        let yara_visible = layer
            .filter(&AnnotationFilter::new().for_source(AnnotationSource::Yara))
            .iter()
            .filter(|a| a.visible)
            .count();
        assert_eq!(yara_visible, 0);
    }

    #[test]
    fn layer_clear() {
        let mut layer = make_layer();
        layer.annotate(0, 1, "x", "#FF0000");
        layer.clear();
        assert_eq!(layer.count(), 0);
    }

    // ── AnnotationFilter ──────────────────────────────────────────────────

    #[test]
    fn filter_by_source() {
        let mut layer = make_layer();
        layer.annotate(0, 1, "user_ann", "#FF0000");
        let yara = Annotation::new(0, 0x100, 4, "yara", AnnotationSource::Yara);
        layer.add(yara);
        let f = AnnotationFilter::new().for_source(AnnotationSource::Yara);
        let results = layer.filter(&f);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn filter_visible_only() {
        let mut layer = make_layer();
        layer.annotate(0, 1, "x", "#FF0000");
        layer.hide_all();
        let f = AnnotationFilter::new().visible_only();
        assert!(layer.filter(&f).is_empty());
    }

    #[test]
    fn filter_label_contains() {
        let mut layer = make_layer();
        layer.annotate(0, 1, "magic_header", "#FF0000");
        layer.annotate(0x10, 1, "version_byte", "#FF0000");
        let f = AnnotationFilter::new().label_contains("magic");
        assert_eq!(layer.filter(&f).len(), 1);
    }

    // ── AnnotationExport / Import ─────────────────────────────────────────

    #[test]
    fn export_and_import_json() {
        let mut layer = make_layer();
        layer.annotate(0x1000, 4, "test", "#FF0000");
        let json = layer.export_json().unwrap();
        assert!(json.contains("test"));

        let mut layer2 = make_layer();
        let count = layer2.import_json(&json).unwrap();
        assert_eq!(count, 1);
    }

    // ── AnnotationImport ──────────────────────────────────────────────────

    #[test]
    fn import_yara_matches() {
        let matches = vec![(0x1000u64, 16usize, "YARA_RULE".to_string())];
        let anns = AnnotationImport::from_yara_matches(&matches, 1);
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].source, AnnotationSource::Yara);
        assert_eq!(anns[0].color, "#FF8800");
    }

    #[test]
    fn import_template_fields() {
        let fields = vec![
            (0u64, 4usize, "magic".to_string()),
            (4, 2, "version".to_string()),
        ];
        let anns = AnnotationImport::from_template_fields(&fields, 100);
        assert_eq!(anns.len(), 2);
        assert_eq!(anns[0].source, AnnotationSource::Template);
    }

    // ── AnnotationRenderer ────────────────────────────────────────────────

    #[test]
    fn renderer_html_contains_label() {
        let a = Annotation::new(1, 0, 4, "header", AnnotationSource::User)
            .with_color("#FF0000")
            .with_tooltip("File header");
        let html = AnnotationRenderer::render_html(&a);
        assert!(html.contains("header"));
        assert!(html.contains("#FF0000"));
    }

    #[test]
    fn renderer_viewport() {
        let a = Annotation::new(1, 0x100, 16, "x", AnnotationSource::Analysis);
        let spans = AnnotationRenderer::render_viewport(&[&a], 0x100, 0x110);
        assert_eq!(spans.len(), 1);
    }

    // ── AnnotationSource display ──────────────────────────────────────────

    #[test]
    fn source_display() {
        assert_eq!(AnnotationSource::User.to_string(), "user");
        assert_eq!(
            AnnotationSource::Custom("myplugin".to_string()).to_string(),
            "myplugin"
        );
    }

    // ── AnnotationLayer debug ─────────────────────────────────────────────

    #[test]
    fn layer_debug() {
        let layer = make_layer();
        let s = format!("{layer:?}");
        assert!(s.contains("AnnotationLayer"));
    }
}
