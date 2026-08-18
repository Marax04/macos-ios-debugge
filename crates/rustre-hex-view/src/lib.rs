//! `rustre-hex-view` — Hex view rendering for terminal and GUI.
//!
//! Provides a trait-based renderer architecture with ANSI and plain-text
//! implementations, plus a full `HexViewState` that wraps a `HexBuffer` with
//! viewport navigation, annotations, bookmarks, diff highlighting, entropy
//! visualization, structure overlay rendering, and floating annotations.

pub mod annotation_layer;
pub mod column_renderer;
pub mod comparison_view;
pub mod diff_mode;
pub mod diff_view;
pub mod hex_renderer;
pub mod highlight_engine;
pub mod search_engine;
pub mod transform_ops;
pub mod virtual_scroll;
pub use rustre_hex::hex_search_engine;
pub mod hex_formatter;
pub mod data_inspector;
pub mod hex_search;
pub mod hex_diff;
pub mod hex_exporter;
pub mod search_bar;

use std::collections::HashMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use rustre_hex::{Bookmark, DiffRegion, HexBuffer, Histogram};

// ─────────────────────────────────────────────────────────────────────────────
// Color types
// ─────────────────────────────────────────────────────────────────────────────

/// An sRGB colour value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    #[must_use]
    pub const fn black() -> Self {
        Self::new(0, 0, 0)
    }
    #[must_use]
    pub const fn white() -> Self {
        Self::new(255, 255, 255)
    }
    #[must_use]
    pub const fn red() -> Self {
        Self::new(200, 40, 40)
    }
    #[must_use]
    pub const fn green() -> Self {
        Self::new(40, 200, 40)
    }
    #[must_use]
    pub const fn blue() -> Self {
        Self::new(40, 40, 200)
    }
    #[must_use]
    pub const fn yellow() -> Self {
        Self::new(220, 200, 0)
    }
    #[must_use]
    pub const fn cyan() -> Self {
        Self::new(0, 200, 200)
    }
    #[must_use]
    pub const fn magenta() -> Self {
        Self::new(200, 0, 200)
    }
    #[must_use]
    pub const fn gray() -> Self {
        Self::new(128, 128, 128)
    }
    #[must_use]
    pub const fn dark_gray() -> Self {
        Self::new(64, 64, 64)
    }
    #[must_use]
    pub const fn orange() -> Self {
        Self::new(230, 140, 0)
    }
    #[must_use]
    pub const fn light_blue() -> Self {
        Self::new(100, 180, 255)
    }
    #[must_use]
    pub const fn light_green() -> Self {
        Self::new(100, 230, 100)
    }
    #[must_use]
    pub const fn pink() -> Self {
        Self::new(255, 150, 180)
    }

    /// Render as an ANSI 24-bit foreground escape sequence.
    #[must_use]
    pub fn ansi_fg(&self) -> String {
        format!("\x1b[38;2;{};{};{}m", self.r, self.g, self.b)
    }

    /// Render as an ANSI 24-bit background escape sequence.
    #[must_use]
    pub fn ansi_bg(&self) -> String {
        format!("\x1b[48;2;{};{};{}m", self.r, self.g, self.b)
    }

    /// Blend this colour toward `other` by `t ∈ [0.0, 1.0]`.
    #[must_use]
    pub fn blend(&self, other: Self, t: f32) -> Self {
        let t = t.clamp(0.0, 1.0);
        let lerp = |a: u8, b: u8| -> u8 {
            let af = f32::from(a);
            let bf = f32::from(b);
            (bf - af).mul_add(t, af).round() as u8
        };
        Self::new(
            lerp(self.r, other.r),
            lerp(self.g, other.g),
            lerp(self.b, other.b),
        )
    }

    /// Convert to a packed `0xRRGGBB` value.
    #[must_use]
    pub const fn to_rgb_u32(self) -> u32 {
        ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Create from a packed `0xRRGGBB` value.
    #[must_use]
    pub const fn from_rgb_u32(v: u32) -> Self {
        Self::new(
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        )
    }

    /// Return a colour suitable for an entropy bar at the given entropy value (0–8).
    /// Low entropy → blue, medium → green, high → red.
    #[must_use]
    pub fn for_entropy(entropy: f64) -> Self {
        let t = (entropy / 8.0).clamp(0.0, 1.0) as f32;
        if t < 0.5 {
            Self::blue().blend(Self::green(), t * 2.0)
        } else {
            Self::green().blend(Self::red(), (t - 0.5) * 2.0)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColorMap
// ─────────────────────────────────────────────────────────────────────────────

/// Maps byte value ranges to display colours.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ColorMap {
    /// `(start, end, fg, bg_opt)` — inclusive byte value range.
    pub ranges: Vec<(u8, u8, Color, Option<Color>)>,
    pub default_fg: Color,
    pub default_bg: Option<Color>,
}

impl ColorMap {
    /// Look up the display colour for a byte value.
    #[must_use]
    pub fn lookup(&self, byte: u8) -> (Color, Option<Color>) {
        for &(lo, hi, fg, bg) in &self.ranges {
            if byte >= lo && byte <= hi {
                return (fg, bg);
            }
        }
        (self.default_fg, self.default_bg)
    }

    /// Add a range mapping.
    pub fn add_range(&mut self, lo: u8, hi: u8, fg: Color, bg: Option<Color>) {
        self.ranges.push((lo, hi, fg, bg));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColorScheme
// ─────────────────────────────────────────────────────────────────────────────

/// Predefined or custom colour schemes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColorScheme {
    Dark,
    Light,
    Monokai,
    Nord,
    Solarized,
    HighContrast,
    Custom(ColorMap),
}

impl ColorScheme {
    /// Return the `ColorMap` for this scheme.
    #[must_use]
    pub fn color_map(&self) -> ColorMap {
        match self {
            Self::Dark => dark_color_map(),
            Self::Light => light_color_map(),
            Self::Monokai => monokai_color_map(),
            Self::Nord => nord_color_map(),
            Self::Solarized => solarized_color_map(),
            Self::HighContrast => high_contrast_color_map(),
            Self::Custom(cm) => cm.clone(),
        }
    }

    /// Return the name of this scheme.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Dark => "Dark",
            Self::Light => "Light",
            Self::Monokai => "Monokai",
            Self::Nord => "Nord",
            Self::Solarized => "Solarized",
            Self::HighContrast => "HighContrast",
            Self::Custom(_) => "Custom",
        }
    }
}

fn dark_color_map() -> ColorMap {
    let mut cm = ColorMap {
        default_fg: Color::new(200, 200, 200),
        default_bg: None,
        ranges: Vec::new(),
    };
    cm.ranges.push((0x00, 0x00, Color::dark_gray(), None));
    cm.ranges
        .push((0x20, 0x7E, Color::new(180, 230, 180), None));
    cm.ranges
        .push((0x80, 0xFF, Color::new(180, 140, 100), None));
    cm
}

fn light_color_map() -> ColorMap {
    let mut cm = ColorMap {
        default_fg: Color::black(),
        default_bg: None,
        ranges: Vec::new(),
    };
    cm.ranges.push((0x00, 0x00, Color::gray(), None));
    cm.ranges.push((0x20, 0x7E, Color::new(0, 100, 0), None));
    cm.ranges.push((0x80, 0xFF, Color::new(100, 50, 0), None));
    cm
}

fn monokai_color_map() -> ColorMap {
    let mut cm = ColorMap {
        default_fg: Color::new(248, 248, 242),
        default_bg: None,
        ranges: Vec::new(),
    };
    cm.ranges.push((0x00, 0x00, Color::new(117, 113, 94), None));
    cm.ranges.push((0x20, 0x7E, Color::new(166, 226, 46), None));
    cm.ranges.push((0x80, 0xFF, Color::new(249, 38, 114), None));
    cm
}

fn nord_color_map() -> ColorMap {
    let mut cm = ColorMap {
        default_fg: Color::new(216, 222, 233),
        default_bg: None,
        ranges: Vec::new(),
    };
    cm.ranges.push((0x00, 0x00, Color::new(76, 86, 106), None));
    cm.ranges
        .push((0x20, 0x7E, Color::new(163, 190, 140), None));
    cm.ranges
        .push((0x80, 0xFF, Color::new(235, 203, 139), None));
    cm
}

fn solarized_color_map() -> ColorMap {
    let mut cm = ColorMap {
        default_fg: Color::new(131, 148, 150),
        default_bg: None,
        ranges: Vec::new(),
    };
    cm.ranges.push((0x00, 0x1F, Color::new(88, 110, 117), None));
    cm.ranges.push((0x20, 0x7E, Color::new(133, 153, 0), None));
    cm.ranges.push((0x7F, 0x7F, Color::new(181, 137, 0), None));
    cm.ranges.push((0x80, 0xFF, Color::new(203, 75, 22), None));
    cm
}

fn high_contrast_color_map() -> ColorMap {
    let mut cm = ColorMap {
        default_fg: Color::white(),
        default_bg: Some(Color::black()),
        ranges: Vec::new(),
    };
    cm.ranges
        .push((0x00, 0x00, Color::gray(), Some(Color::black())));
    cm.ranges
        .push((0x20, 0x7E, Color::yellow(), Some(Color::black())));
    cm.ranges
        .push((0x80, 0xFF, Color::cyan(), Some(Color::black())));
    cm
}

// ─────────────────────────────────────────────────────────────────────────────
// OffsetBase
// ─────────────────────────────────────────────────────────────────────────────

/// Numeric base for offset display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffsetBase {
    Hex,
    Decimal,
    Octal,
}

impl OffsetBase {
    /// Format `offset` in this base.
    #[must_use]
    pub fn format(&self, offset: usize) -> String {
        match self {
            Self::Hex => format!("{offset:08X}"),
            Self::Decimal => format!("{offset:010}"),
            Self::Octal => format!("{offset:011o}"),
        }
    }

    /// Format `offset` with base prefix (e.g. `0x`, `0o`).
    #[must_use]
    pub fn format_prefixed(&self, offset: usize) -> String {
        match self {
            Self::Hex => format!("0x{offset:08X}"),
            Self::Decimal => format!("{offset}"),
            Self::Octal => format!("0o{offset:o}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexViewConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the hex view renderer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexViewConfig {
    pub bytes_per_row: usize,
    pub group_size: usize,
    pub show_offset: bool,
    pub offset_base: OffsetBase,
    pub show_ascii: bool,
    pub show_annotations: bool,
    pub color_scheme: ColorScheme,
    /// Number of visible rows (used for page-up/down).
    pub visible_rows: usize,
    /// Show diff highlights when two buffers are loaded.
    pub show_diff: bool,
    /// Show entropy bar alongside each row.
    pub show_entropy_bar: bool,
    /// Block size for entropy computation per row.
    pub entropy_block_size: usize,
    /// Show structure overlay field labels.
    pub show_structure_overlay: bool,
    /// Use uppercase hex digits.
    pub uppercase_hex: bool,
}

impl Default for HexViewConfig {
    fn default() -> Self {
        Self {
            bytes_per_row: 16,
            group_size: 1,
            show_offset: true,
            offset_base: OffsetBase::Hex,
            show_ascii: true,
            show_annotations: true,
            color_scheme: ColorScheme::Dark,
            visible_rows: 24,
            show_diff: false,
            show_entropy_bar: false,
            entropy_block_size: 256,
            show_structure_overlay: false,
            uppercase_hex: true,
        }
    }
}

impl HexViewConfig {
    /// Return a config tuned for 16-byte-wide diff display.
    #[must_use]
    pub fn for_diff() -> Self {
        Self {
            show_diff: true,
            ..Self::default()
        }
    }

    /// Return a config with entropy bars enabled.
    #[must_use]
    pub fn with_entropy() -> Self {
        Self {
            show_entropy_bar: true,
            ..Self::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Annotation
// ─────────────────────────────────────────────────────────────────────────────

/// A labelled, coloured region in the buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub offset: usize,
    pub len: usize,
    pub label: String,
    pub color: Color,
}

impl Annotation {
    /// Return the byte range covered by this annotation.
    #[must_use]
    pub const fn range(&self) -> Range<usize> {
        self.offset..self.offset.saturating_add(self.len)
    }

    /// Return `true` if this annotation overlaps `range`.
    #[must_use]
    pub const fn overlaps(&self, range: Range<usize>) -> bool {
        self.offset < range.end && self.offset.saturating_add(self.len) > range.start
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FloatingAnnotation
// ─────────────────────────────────────────────────────────────────────────────

/// A floating annotation displayed at a fixed view column offset (e.g. a tooltip
/// shown in the margin or inline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloatingAnnotation {
    /// Byte offset in the buffer.
    pub offset: usize,
    /// Text content.
    pub text: String,
    /// Colour for the floating label.
    pub color: Color,
    /// Whether to show as an inline tooltip vs. a margin label.
    pub inline: bool,
}

impl FloatingAnnotation {
    /// Create a new floating annotation.
    #[must_use]
    pub fn new(offset: usize, text: impl Into<String>, color: Color, inline: bool) -> Self {
        Self {
            offset,
            text: text.into(),
            color,
            inline,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationLayer
// ─────────────────────────────────────────────────────────────────────────────

/// A sortable, merge-aware collection of annotations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnnotationLayer {
    pub annotations: Vec<Annotation>,
    pub floating: Vec<FloatingAnnotation>,
}

impl AnnotationLayer {
    /// Create an empty layer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            annotations: Vec::new(),
            floating: Vec::new(),
        }
    }

    /// Add an annotation, keeping the list sorted by offset.
    pub fn add(&mut self, ann: Annotation) {
        self.annotations.push(ann);
        self.annotations.sort_by_key(|a| a.offset);
    }

    /// Add a floating annotation.
    pub fn add_floating(&mut self, ann: FloatingAnnotation) {
        self.floating.push(ann);
        self.floating.sort_by_key(|a| a.offset);
    }

    /// Return all annotations that overlap with `offset..offset+len`.
    #[must_use]
    pub fn overlapping(&self, offset: usize, len: usize) -> Vec<&Annotation> {
        let end = offset.saturating_add(len);
        self.annotations
            .iter()
            .filter(|a| a.offset < end && a.offset.saturating_add(a.len) > offset)
            .collect()
    }

    /// Find annotations that start at `offset`.
    #[must_use]
    pub fn at_offset(&self, offset: usize) -> Vec<&Annotation> {
        self.annotations
            .iter()
            .filter(|a| a.offset == offset)
            .collect()
    }

    /// Return floating annotations at the given buffer offset.
    #[must_use]
    pub fn floating_at(&self, offset: usize) -> Vec<&FloatingAnnotation> {
        self.floating
            .iter()
            .filter(|f| f.offset == offset)
            .collect()
    }

    /// Check whether two annotations overlap.
    #[must_use]
    pub fn has_overlap(&self) -> bool {
        for i in 0..self.annotations.len() {
            for j in (i + 1)..self.annotations.len() {
                let a = &self.annotations[i];
                let b = &self.annotations[j];
                if a.offset < b.offset.saturating_add(b.len) && a.offset.saturating_add(a.len) > b.offset {
                    return true;
                }
            }
        }
        false
    }

    /// Merge all overlapping annotations into non-overlapping super-regions.
    pub fn merge_overlapping(&mut self) {
        if self.annotations.is_empty() {
            return;
        }
        self.annotations.sort_by_key(|a| a.offset);
        let mut merged: Vec<Annotation> = Vec::new();
        for ann in self.annotations.drain(..) {
            if let Some(last) = merged.last_mut() {
                let last_end = last.offset.saturating_add(last.len);
                if ann.offset < last_end {
                    let new_end = last_end.max(ann.offset.saturating_add(ann.len));
                    last.len = new_end - last.offset;
                    last.label = format!("{} / {}", last.label, ann.label);
                    continue;
                }
            }
            merged.push(ann);
        }
        self.annotations = merged;
    }

    /// Remove all annotations whose range intersects with `range`.
    pub fn remove_in_range(&mut self, range: Range<usize>) {
        self.annotations
            .retain(|a| a.offset >= range.end || a.offset.saturating_add(a.len) <= range.start);
    }

    /// Return the total number of byte-level annotations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.annotations.len()
    }

    /// Return `true` if there are no annotations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColorSpan
// ─────────────────────────────────────────────────────────────────────────────

/// A run of rendered characters with a single colour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorSpan {
    /// Start column in the rendered line (character index).
    pub start: usize,
    /// End column (exclusive).
    pub end: usize,
    pub fg: Color,
    pub bg: Option<Color>,
    pub bold: bool,
    pub underline: bool,
}

impl ColorSpan {
    /// Create a simple foreground-only span.
    #[must_use]
    pub const fn fg(start: usize, end: usize, fg: Color) -> Self {
        Self {
            start,
            end,
            fg,
            bg: None,
            bold: false,
            underline: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyBar
// ─────────────────────────────────────────────────────────────────────────────

/// Rendered entropy indicator for a single row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBar {
    /// Entropy value in [0, 8].
    pub entropy: f64,
    /// Colour representing this entropy level.
    pub color: Color,
    /// ASCII art bar of fixed width 8.
    pub bar: String,
}

impl EntropyBar {
    /// Build an entropy bar for the given entropy value.
    #[must_use]
    pub fn build(entropy: f64) -> Self {
        let color = Color::for_entropy(entropy);
        let filled = ((entropy / 8.0) * 8.0).round() as usize;
        let bar: String = (0..8).map(|i| if i < filled { '#' } else { '.' }).collect();
        Self {
            entropy,
            color,
            bar,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffHighlight
// ─────────────────────────────────────────────────────────────────────────────

/// Per-byte diff status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiffStatus {
    Same,
    Changed,
    OnlyInLeft,
    OnlyInRight,
}

impl DiffStatus {
    /// Return the colour associated with this diff status.
    #[must_use]
    pub const fn color(self) -> Option<Color> {
        match self {
            Self::Same => None,
            Self::Changed => Some(Color::yellow()),
            Self::OnlyInLeft => Some(Color::red()),
            Self::OnlyInRight => Some(Color::green()),
        }
    }
}

/// Diff highlighting state for the view.
#[derive(Debug, Clone, Default)]
pub struct DiffHighlightMap {
    /// Byte offset → diff status.
    map: HashMap<usize, DiffStatus>,
}

impl DiffHighlightMap {
    /// Build from a list of `DiffRegion`s against the left buffer.
    #[must_use]
    pub fn from_diff_regions(regions: &[DiffRegion], right_len: usize) -> Self {
        let mut map = HashMap::new();
        for region in regions {
            let end = region.offset.saturating_add(region.len);
            // Changed bytes exist in both sides
            let left_len_region = region.left.len();
            let right_len_region = region.right.len();
            let common = left_len_region.min(right_len_region);
            for i in 0..common {
                let Some(pos) = region.offset.checked_add(i) else { break };
                map.insert(pos, DiffStatus::Changed);
            }
            // Extra bytes only in left
            for i in common..left_len_region {
                let Some(pos) = region.offset.checked_add(i) else { break };
                if pos >= end {
                    break;
                }
                map.insert(pos, DiffStatus::OnlyInLeft);
            }
            // Extra bytes only in right
            for i in common..right_len_region {
                let Some(pos) = region.offset.checked_add(i) else { break };
                if pos < right_len {
                    map.insert(pos, DiffStatus::OnlyInRight);
                }
            }
        }
        Self { map }
    }

    /// Return the diff status for byte at `offset`.
    #[must_use]
    pub fn status(&self, offset: usize) -> DiffStatus {
        self.map.get(&offset).copied().unwrap_or(DiffStatus::Same)
    }

    /// Return `true` if any byte is marked as changed.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.map.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructureOverlayView
// ─────────────────────────────────────────────────────────────────────────────

/// A rendered structure field overlaid on the hex view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldOverlay {
    /// Byte offset in the buffer.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Field name.
    pub name: String,
    /// Type description string.
    pub type_str: String,
    /// Colour for this field.
    pub color: Color,
}

impl StructFieldOverlay {
    /// Create a new structure field overlay entry.
    #[must_use]
    pub fn new(
        offset: usize,
        size: usize,
        name: impl Into<String>,
        type_str: impl Into<String>,
        color: Color,
    ) -> Self {
        Self {
            offset,
            size,
            name: name.into(),
            type_str: type_str.into(),
            color,
        }
    }

    /// Return `true` if this field covers `offset`.
    #[must_use]
    pub const fn contains(&self, offset: usize) -> bool {
        offset >= self.offset && offset < self.offset + self.size
    }
}

/// A collection of structure field overlays for the view.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructureOverlayView {
    pub fields: Vec<StructFieldOverlay>,
}

impl StructureOverlayView {
    /// Create an empty view.
    #[must_use]
    pub const fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// Add a field.
    pub fn add(&mut self, field: StructFieldOverlay) {
        self.fields.push(field);
        self.fields.sort_by_key(|f| f.offset);
    }

    /// Return all fields that cover the given byte offset.
    #[must_use]
    pub fn at_offset(&self, offset: usize) -> Vec<&StructFieldOverlay> {
        self.fields.iter().filter(|f| f.contains(offset)).collect()
    }

    /// Return the colour to use for byte at `offset`, or `None` if no overlay.
    #[must_use]
    pub fn color_at(&self, offset: usize) -> Option<Color> {
        self.fields
            .iter()
            .find(|f| f.contains(offset))
            .map(|f| f.color)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RenderedLine
// ─────────────────────────────────────────────────────────────────────────────

/// A single rendered line of the hex view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedLine {
    pub offset_str: String,
    pub hex_str: String,
    pub ascii_str: String,
    pub spans: Vec<ColorSpan>,
    /// Optional entropy bar for this row.
    pub entropy_bar: Option<EntropyBar>,
    /// Optional floating annotation text attached to this line.
    pub floating_labels: Vec<String>,
}

impl RenderedLine {
    /// Combine offset + hex + ascii into a single display string.
    #[must_use]
    pub fn to_display(&self) -> String {
        let mut s = String::new();
        if !self.offset_str.is_empty() {
            s.push_str(&self.offset_str);
            s.push_str("  ");
        }
        s.push_str(&self.hex_str);
        if !self.ascii_str.is_empty() {
            s.push_str("  |");
            s.push_str(&self.ascii_str);
            s.push('|');
        }
        if let Some(ref bar) = self.entropy_bar {
            s.push_str("  [");
            s.push_str(&bar.bar);
            s.push(']');
        }
        s
    }

    /// Combine all floating label text into a single string.
    #[must_use]
    pub fn floating_label_text(&self) -> String {
        self.floating_labels.join(", ")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexViewRenderer trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for rendering a single row of the hex view.
pub trait HexViewRenderer {
    /// Render one row at `offset` using `bytes`, with optional annotations.
    fn render_line(&self, offset: usize, bytes: &[u8], annotations: &[Annotation]) -> RenderedLine;

    /// Render the full buffer with `config` and return all lines.
    fn render_all(
        &self,
        data: &[u8],
        base_offset: usize,
        config: &HexViewConfig,
        annotations: &AnnotationLayer,
    ) -> Vec<RenderedLine> {
        let bpr = config.bytes_per_row.max(1);
        let mut lines = Vec::with_capacity(data.len().div_ceil(bpr));
        let mut pos = 0usize;
        while pos < data.len() {
            let end = (pos + bpr).min(data.len());
            let row = &data[pos..end];
            let ann_slice = annotations.overlapping(base_offset + pos, row.len());
            let ann_owned: Vec<Annotation> = ann_slice.into_iter().cloned().collect();
            lines.push(self.render_line(base_offset + pos, row, &ann_owned));
            pos += bpr;
        }
        lines
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PlainHexRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Renders hex view lines as plain text (no colour escapes).
pub struct PlainHexRenderer {
    pub config: HexViewConfig,
}

impl PlainHexRenderer {
    /// Create a new plain renderer with the given config.
    #[must_use]
    pub const fn new(config: HexViewConfig) -> Self {
        Self { config }
    }
}

impl HexViewRenderer for PlainHexRenderer {
    fn render_line(
        &self,
        offset: usize,
        bytes: &[u8],
        _annotations: &[Annotation],
    ) -> RenderedLine {
        let offset_str = if self.config.show_offset {
            self.config.offset_base.format(offset)
        } else {
            String::new()
        };

        let bpr = self.config.bytes_per_row;
        let gs = self.config.group_size.max(1);
        use std::fmt::Write as _;
        let mut hex_str = String::with_capacity(bpr * 3);
        for (i, &b) in bytes.iter().enumerate() {
            if i > 0 && i.is_multiple_of(gs) {
                hex_str.push(' ');
            }
            if self.config.uppercase_hex {
                let _ = write!(hex_str, "{b:02X}");
            } else {
                let _ = write!(hex_str, "{b:02x}");
            }
        }
        let mut filled = bytes.len();
        while filled < bpr {
            if filled > 0 && filled.is_multiple_of(gs) {
                hex_str.push(' ');
            }
            hex_str.push_str("  ");
            filled += 1;
        }

        let ascii_str = if self.config.show_ascii {
            bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect()
        } else {
            String::new()
        };

        let entropy_bar = if self.config.show_entropy_bar {
            let h = rustre_hex::entropy(bytes, bytes.len().max(1));
            let e = h.first().copied().unwrap_or(0.0);
            Some(EntropyBar::build(e))
        } else {
            None
        };

        RenderedLine {
            offset_str,
            hex_str,
            ascii_str,
            spans: Vec::new(),
            entropy_bar,
            floating_labels: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnsiHexRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Renders hex view lines as ANSI escape-code coloured strings.
pub struct AnsiHexRenderer {
    pub config: HexViewConfig,
    /// Optional diff highlights.
    pub diff: Option<DiffHighlightMap>,
    /// Optional structure overlay.
    pub overlay: Option<StructureOverlayView>,
}

impl AnsiHexRenderer {
    const RESET: &'static str = "\x1b[0m";

    /// Create a new ANSI renderer with the given config and no diff/overlay.
    #[must_use]
    pub const fn new(config: HexViewConfig) -> Self {
        Self {
            config,
            diff: None,
            overlay: None,
        }
    }

    /// Attach a diff highlight map.
    #[must_use]
    pub fn with_diff(mut self, diff: DiffHighlightMap) -> Self {
        self.diff = Some(diff);
        self
    }

    /// Attach a structure overlay.
    #[must_use]
    pub fn with_overlay(mut self, overlay: StructureOverlayView) -> Self {
        self.overlay = Some(overlay);
        self
    }

    /// Render a full line to an ANSI-coloured string.
    #[must_use]
    pub fn render_line_ansi(
        &self,
        offset: usize,
        bytes: &[u8],
        annotations: &[Annotation],
    ) -> String {
        let line = self.render_line(offset, bytes, annotations);
        let mut out = String::new();
        if !line.offset_str.is_empty() {
            out.push_str(&Color::gray().ansi_fg());
            out.push_str(&line.offset_str);
            out.push_str(Self::RESET);
            out.push_str("  ");
        }
        out.push_str(&line.hex_str);
        if !line.ascii_str.is_empty() {
            out.push_str("  |");
            out.push_str(&line.ascii_str);
            out.push('|');
        }
        if let Some(ref bar) = line.entropy_bar {
            out.push_str("  ");
            out.push_str(&bar.color.ansi_fg());
            out.push('[');
            out.push_str(&bar.bar);
            out.push(']');
            out.push_str(Self::RESET);
        }
        if !line.floating_labels.is_empty() {
            out.push_str("  // ");
            out.push_str(&line.floating_labels.join(", "));
        }
        out
    }
}

impl HexViewRenderer for AnsiHexRenderer {
    fn render_line(&self, offset: usize, bytes: &[u8], annotations: &[Annotation]) -> RenderedLine {
        let cm = self.config.color_scheme.color_map();
        let offset_str = if self.config.show_offset {
            self.config.offset_base.format(offset)
        } else {
            String::new()
        };

        let bpr = self.config.bytes_per_row;
        let gs = self.config.group_size.max(1);

        // Build annotation map: local byte index → colour
        let mut ann_map: HashMap<usize, Color> = HashMap::new();
        if self.config.show_annotations {
            for ann in annotations {
                let start = ann.offset.max(offset);
                let end = ann.offset.saturating_add(ann.len).min(offset.saturating_add(bytes.len()));
                for i in start..end {
                    ann_map.insert(i - offset, ann.color);
                }
            }
        }

        use std::fmt::Write as _;
        let mut hex_str = String::with_capacity(bpr * 16);
        let mut ascii_str = String::with_capacity(if self.config.show_ascii { bpr } else { 0 });
        let mut spans: Vec<ColorSpan> = Vec::with_capacity(bytes.len());
        let mut hex_col = 0usize;

        for (i, &b) in bytes.iter().enumerate() {
            if i > 0 && i.is_multiple_of(gs) {
                hex_str.push(' ');
                hex_col += 1;
            }

            // Priority: diff > structure overlay > annotation > color map
            let (fg, bg_opt) = if let Some(ref diff) = self.diff {
                let status = diff.status(offset + i);
                if let Some(diff_color) = status.color() {
                    (diff_color, Some(Color::new(30, 30, 30)))
                } else if let Some(&ann_color) = ann_map.get(&i) {
                    (ann_color, Some(Color::new(30, 30, 30)))
                } else if let Some(ref ov) = self.overlay {
                    if let Some(ov_color) = ov.color_at(offset + i) {
                        (ov_color, None)
                    } else {
                        cm.lookup(b)
                    }
                } else {
                    cm.lookup(b)
                }
            } else if let Some(&ann_color) = ann_map.get(&i) {
                (ann_color, Some(Color::new(30, 30, 30)))
            } else if let Some(ref ov) = self.overlay {
                if let Some(ov_color) = ov.color_at(offset + i) {
                    (ov_color, None)
                } else {
                    cm.lookup(b)
                }
            } else {
                cm.lookup(b)
            };

            spans.push(ColorSpan {
                start: hex_col,
                end: hex_col + 2,
                fg,
                bg: bg_opt,
                bold: false,
                underline: false,
            });

            hex_str.push_str(&fg.ansi_fg());
            if let Some(bg) = bg_opt {
                hex_str.push_str(&bg.ansi_bg());
            }
            if self.config.uppercase_hex {
                let _ = write!(hex_str, "{b:02X}");
            } else {
                let _ = write!(hex_str, "{b:02x}");
            }
            hex_str.push_str(Self::RESET);
            hex_col += 2;
        }

        // Pad remaining bytes
        let mut filled = bytes.len();
        while filled < bpr {
            if filled > 0 && filled.is_multiple_of(gs) {
                hex_str.push(' ');
            }
            hex_str.push_str("  ");
            filled += 1;
        }

        if self.config.show_ascii {
            for &b in bytes {
                let ch = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                };
                ascii_str.push(ch);
            }
        }

        let entropy_bar = if self.config.show_entropy_bar {
            let h = rustre_hex::entropy(bytes, bytes.len().max(1));
            let e = h.first().copied().unwrap_or(0.0);
            Some(EntropyBar::build(e))
        } else {
            None
        };

        RenderedLine {
            offset_str,
            hex_str,
            ascii_str,
            spans,
            entropy_bar,
            floating_labels: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ViewportState
// ─────────────────────────────────────────────────────────────────────────────

/// The scroll/cursor state for a hex view.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ViewportState {
    /// Byte offset of the first visible row.
    pub top_offset: usize,
    /// Current cursor position (byte offset in buffer).
    pub cursor: usize,
    /// Active selection range.
    pub selection: Option<Range<usize>>,
}

impl ViewportState {
    /// Return `true` if `offset` is within the visible window given config.
    #[must_use]
    pub fn is_visible(&self, offset: usize, config: &HexViewConfig) -> bool {
        let bpr = config.bytes_per_row.max(1);
        let visible_bytes = bpr * config.visible_rows;
        offset >= self.top_offset && offset < self.top_offset + visible_bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexViewState
// ─────────────────────────────────────────────────────────────────────────────

/// Full interactive hex view state combining buffer, config, annotations, bookmarks,
/// diff info, structure overlay, and navigation.
pub struct HexViewState {
    pub buffer: HexBuffer,
    pub config: HexViewConfig,
    pub annotations: AnnotationLayer,
    pub bookmarks: Vec<Bookmark>,
    pub viewport: ViewportState,
    /// Optional second buffer for diff mode.
    pub diff_buffer: Option<HexBuffer>,
    /// Cached diff highlight map (rebuilt when `diff_buffer` changes).
    pub diff_highlights: DiffHighlightMap,
    /// Structure overlay fields for rendering.
    pub structure_overlay: StructureOverlayView,
    /// Cached per-row entropy values (block = `bytes_per_row`).
    entropy_cache: Option<Vec<f64>>,
}

impl HexViewState {
    /// Create a new `HexViewState` with default config.
    #[must_use]
    pub fn new(buffer: HexBuffer) -> Self {
        Self {
            buffer,
            config: HexViewConfig::default(),
            annotations: AnnotationLayer::new(),
            bookmarks: Vec::new(),
            viewport: ViewportState::default(),
            diff_buffer: None,
            diff_highlights: DiffHighlightMap::default(),
            structure_overlay: StructureOverlayView::new(),
            entropy_cache: None,
        }
    }

    /// Create a state with a custom config.
    #[must_use]
    pub fn with_config(buffer: HexBuffer, config: HexViewConfig) -> Self {
        Self {
            config,
            ..Self::new(buffer)
        }
    }

    /// Set a second buffer for diff mode and recompute the highlight map.
    pub fn set_diff_buffer(&mut self, other: HexBuffer) {
        let regions = rustre_hex::HexDiff::compare(&self.buffer, &other);
        self.diff_highlights = DiffHighlightMap::from_diff_regions(&regions, other.len());
        self.diff_buffer = Some(other);
        self.config.show_diff = true;
    }

    /// Clear the diff buffer and disable diff mode.
    pub fn clear_diff(&mut self) {
        self.diff_buffer = None;
        self.diff_highlights = DiffHighlightMap::default();
        self.config.show_diff = false;
    }

    /// Invalidate the entropy cache (call after buffer edits).
    pub fn invalidate_entropy(&mut self) {
        self.entropy_cache = None;
    }

    /// Return the entropy for the row containing `offset`.
    #[must_use]
    pub fn row_entropy(&mut self, offset: usize) -> f64 {
        let bpr = self.config.bytes_per_row.max(1);
        if self.entropy_cache.is_none() {
            self.entropy_cache = Some(rustre_hex::entropy(&self.buffer.data, bpr));
        }
        let row_idx = offset / bpr;
        self.entropy_cache
            .as_ref()
            .and_then(|v| v.get(row_idx))
            .copied()
            .unwrap_or(0.0)
    }

    /// Build an entropy visualisation as a vec of (offset, entropy) pairs, one per row.
    #[must_use]
    pub fn entropy_rows(&self) -> Vec<(usize, f64)> {
        let bpr = self.config.bytes_per_row.max(1);
        rustre_hex::entropy(&self.buffer.data, bpr)
            .into_iter()
            .enumerate()
            .map(|(i, e)| (i * bpr, e))
            .collect()
    }

    /// Build a histogram over the entire buffer.
    #[must_use]
    pub fn histogram(&self) -> Histogram {
        self.buffer.histogram()
    }

    /// Scroll the viewport so that `offset` is visible (top of view).
    pub fn scroll_to(&mut self, offset: usize) {
        let bpr = self.config.bytes_per_row.max(1);
        let row = offset / bpr;
        self.viewport.top_offset = row * bpr;
    }

    /// Move the cursor to an absolute offset.
    pub fn go_to_offset(&mut self, offset: usize) {
        let clamped = offset.min(self.buffer.len().saturating_sub(1));
        self.viewport.cursor = clamped;
        self.scroll_to(clamped);
    }

    /// Move cursor one byte to the left.
    pub fn cursor_move_left(&mut self) {
        if self.viewport.cursor > 0 {
            self.viewport.cursor -= 1;
            self.ensure_cursor_visible();
        }
    }

    /// Move cursor one byte to the right.
    pub fn cursor_move_right(&mut self) {
        if self.viewport.cursor + 1 < self.buffer.len() {
            self.viewport.cursor += 1;
            self.ensure_cursor_visible();
        }
    }

    /// Move cursor one row up.
    pub fn cursor_move_up(&mut self) {
        let bpr = self.config.bytes_per_row.max(1);
        self.viewport.cursor = self.viewport.cursor.saturating_sub(bpr);
        self.ensure_cursor_visible();
    }

    /// Move cursor one row down.
    pub fn cursor_move_down(&mut self) {
        let bpr = self.config.bytes_per_row.max(1);
        let new_cursor = self.viewport.cursor + bpr;
        if new_cursor < self.buffer.len() {
            self.viewport.cursor = new_cursor;
            self.ensure_cursor_visible();
        }
    }

    /// Scroll one page up.
    pub fn page_up(&mut self) {
        let bpr = self.config.bytes_per_row.max(1);
        let page = bpr * self.config.visible_rows;
        self.viewport.top_offset = self.viewport.top_offset.saturating_sub(page);
        self.viewport.cursor = self.viewport.cursor.saturating_sub(page);
    }

    /// Scroll one page down.
    pub fn page_down(&mut self) {
        let bpr = self.config.bytes_per_row.max(1);
        let page = bpr * self.config.visible_rows;
        let max_top = self.max_top_offset();
        self.viewport.top_offset = (self.viewport.top_offset + page).min(max_top);
        let new_cursor = self.viewport.cursor + page;
        if new_cursor < self.buffer.len() {
            self.viewport.cursor = new_cursor;
        }
    }

    /// Jump to the start of the buffer.
    pub const fn go_to_start(&mut self) {
        self.viewport.cursor = 0;
        self.viewport.top_offset = 0;
    }

    /// Jump to the end of the buffer.
    pub fn go_to_end(&mut self) {
        let end = self.buffer.len().saturating_sub(1);
        self.viewport.cursor = end;
        self.scroll_to(end);
    }

    /// Begin a selection at the current cursor.
    pub const fn begin_selection(&mut self) {
        self.viewport.selection = Some(self.viewport.cursor..self.viewport.cursor);
    }

    /// Extend the selection to the current cursor.
    pub const fn extend_selection(&mut self) {
        if let Some(ref mut sel) = self.viewport.selection {
            let start = sel.start;
            let end = self.viewport.cursor;
            *sel = if start <= end {
                start..end + 1
            } else {
                end..start + 1
            };
        }
    }

    /// Clear the selection.
    pub const fn clear_selection(&mut self) {
        self.viewport.selection = None;
    }

    fn ensure_cursor_visible(&mut self) {
        let bpr = self.config.bytes_per_row.max(1);
        let cursor_row = self.viewport.cursor / bpr;
        let top_row = self.viewport.top_offset / bpr;
        let visible_rows = self.config.visible_rows.max(1);
        if cursor_row < top_row {
            self.viewport.top_offset = cursor_row * bpr;
        } else if cursor_row >= top_row + visible_rows {
            self.viewport.top_offset = (cursor_row + 1 - visible_rows) * bpr;
        }
    }

    fn max_top_offset(&self) -> usize {
        let bpr = self.config.bytes_per_row.max(1);
        let total_rows = self.buffer.len().div_ceil(bpr);
        let visible = self.config.visible_rows;
        if total_rows > visible {
            (total_rows - visible) * bpr
        } else {
            0
        }
    }

    /// Render all visible rows using the `AnsiHexRenderer`.
    #[must_use]
    pub fn render_visible_ansi(&self) -> Vec<String> {
        let bpr = self.config.bytes_per_row.max(1);
        let mut renderer = AnsiHexRenderer::new(self.config.clone());
        if self.config.show_diff {
            renderer = renderer.with_diff(DiffHighlightMap {
                map: self.diff_highlights.map.clone(),
            });
        }
        if self.config.show_structure_overlay {
            renderer = renderer.with_overlay(StructureOverlayView {
                fields: self.structure_overlay.fields.clone(),
            });
        }
        let top = self.viewport.top_offset;
        let end = (top + bpr * self.config.visible_rows).min(self.buffer.len());
        if top >= self.buffer.len() {
            return Vec::new();
        }
        let visible = &self.buffer.data[top..end];
        renderer
            .render_all(visible, top, &self.config, &self.annotations)
            .into_iter()
            .map(|l| l.to_display())
            .collect()
    }

    /// Render all visible rows as plain text.
    #[must_use]
    pub fn render_visible_plain(&self) -> Vec<String> {
        let bpr = self.config.bytes_per_row.max(1);
        let renderer = PlainHexRenderer::new(self.config.clone());
        let top = self.viewport.top_offset;
        let end = (top + bpr * self.config.visible_rows).min(self.buffer.len());
        if top >= self.buffer.len() {
            return Vec::new();
        }
        let visible = &self.buffer.data[top..end];
        renderer
            .render_all(visible, top, &self.config, &self.annotations)
            .into_iter()
            .map(|l| l.to_display())
            .collect()
    }

    /// Return the number of rows needed to display the entire buffer.
    #[must_use]
    pub fn total_rows(&self) -> usize {
        let bpr = self.config.bytes_per_row.max(1);
        self.buffer.len().div_ceil(bpr)
    }

    /// Return the currently selected bytes, or `None` if no selection is active.
    #[must_use]
    pub fn selected_bytes(&self) -> Option<&[u8]> {
        self.viewport.selection.as_ref().and_then(|sel| {
            if sel.start < self.buffer.len() {
                let end = sel.end.min(self.buffer.len());
                Some(&self.buffer.data[sel.start..end])
            } else {
                None
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// format_hex_dump — classic hex dump formatter
// ─────────────────────────────────────────────────────────────────────────────

/// Format `data` as a classic `xxd`-style hex dump starting at `base_offset`.
#[must_use]
pub fn format_hex_dump(data: &[u8], base_offset: usize) -> String {
    let config = HexViewConfig::default();
    let renderer = PlainHexRenderer::new(config.clone());
    let layer = AnnotationLayer::new();
    renderer
        .render_all(data, base_offset, &config, &layer)
        .into_iter()
        .map(|l| l.to_display())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Format `data` as ANSI-coloured hex dump.
#[must_use]
pub fn format_hex_dump_ansi(data: &[u8], base_offset: usize) -> String {
    let config = HexViewConfig::default();
    let renderer = AnsiHexRenderer::new(config.clone());
    let layer = AnnotationLayer::new();
    renderer
        .render_all(data, base_offset, &config, &layer)
        .into_iter()
        .map(|l| l.to_display())
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_buf() -> HexBuffer {
        HexBuffer::new((0u8..=255u8).collect())
    }

    // ── Color ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_color_ansi_fg() {
        let c = Color::new(255, 128, 0);
        let s = c.ansi_fg();
        assert!(s.contains("255"));
        assert!(s.starts_with("\x1b[38;2;"));
    }

    #[test]
    fn test_color_ansi_bg() {
        let c = Color::red();
        let s = c.ansi_bg();
        assert!(s.starts_with("\x1b[48;2;"));
    }

    #[test]
    fn test_color_blend() {
        let a = Color::black();
        let b = Color::white();
        let mid = a.blend(b, 0.5);
        assert_eq!(mid.r, 128);
        assert_eq!(mid.g, 128);
        assert_eq!(mid.b, 128);
    }

    #[test]
    fn test_color_rgb_round_trip() {
        let c = Color::new(10, 20, 30);
        let v = c.to_rgb_u32();
        let c2 = Color::from_rgb_u32(v);
        assert_eq!(c, c2);
    }

    #[test]
    fn test_color_for_entropy() {
        // Zero entropy → blue-ish
        let low = Color::for_entropy(0.0);
        // Full entropy → red-ish
        let high = Color::for_entropy(8.0);
        assert!(high.r > low.r);
    }

    // ── OffsetBase ────────────────────────────────────────────────────────────

    #[test]
    fn test_offset_hex() {
        assert_eq!(OffsetBase::Hex.format(0x1000), "00001000");
    }

    #[test]
    fn test_offset_decimal() {
        assert_eq!(OffsetBase::Decimal.format(4096), "0000004096");
    }

    #[test]
    fn test_offset_octal() {
        let s = OffsetBase::Octal.format(8);
        assert!(s.ends_with('0') || s.contains('1'));
    }

    #[test]
    fn test_offset_prefixed_hex() {
        assert!(OffsetBase::Hex.format_prefixed(0x100).starts_with("0x"));
    }

    // ── ColorMap ──────────────────────────────────────────────────────────────

    #[test]
    fn test_colormap_lookup_default() {
        let cm = dark_color_map();
        let (fg, _) = cm.lookup(0x50);
        assert_ne!(fg, cm.default_fg);
    }

    #[test]
    fn test_colormap_lookup_null() {
        let cm = dark_color_map();
        let (fg, _) = cm.lookup(0x00);
        assert_eq!(fg, Color::dark_gray());
    }

    // ── PlainHexRenderer ──────────────────────────────────────────────────────

    #[test]
    fn test_plain_render_line_basic() {
        let renderer = PlainHexRenderer::new(HexViewConfig::default());
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let line = renderer.render_line(0, &data, &[]);
        assert!(line.hex_str.contains("DE"));
        assert!(line.hex_str.contains("AD"));
        assert_eq!(line.offset_str, "00000000");
    }

    #[test]
    fn test_plain_render_ascii() {
        let renderer = PlainHexRenderer::new(HexViewConfig::default());
        let data = b"Hello";
        let line = renderer.render_line(0, data, &[]);
        assert_eq!(line.ascii_str, "Hello");
    }

    #[test]
    fn test_plain_render_no_offset() {
        let cfg = HexViewConfig {
            show_offset: false,
            ..HexViewConfig::default()
        };
        let renderer = PlainHexRenderer::new(cfg);
        let line = renderer.render_line(0, &[0xAA], &[]);
        assert!(line.offset_str.is_empty());
    }

    #[test]
    fn test_plain_render_grouping() {
        let cfg = HexViewConfig {
            group_size: 4,
            ..HexViewConfig::default()
        };
        let renderer = PlainHexRenderer::new(cfg);
        let data = [0u8; 8];
        let line = renderer.render_line(0, &data, &[]);
        assert!(line.hex_str.contains(' '));
    }

    // ── AnsiHexRenderer ───────────────────────────────────────────────────────

    #[test]
    fn test_ansi_render_contains_escape() {
        let renderer = AnsiHexRenderer::new(HexViewConfig::default());
        let data = [0x41u8];
        let s = renderer.render_line_ansi(0, &data, &[]);
        assert!(s.contains('\x1b'));
    }

    #[test]
    fn test_ansi_render_line_spans() {
        let renderer = AnsiHexRenderer::new(HexViewConfig::default());
        let data = [0xAA, 0xBB, 0xCC];
        let line = renderer.render_line(0, &data, &[]);
        assert_eq!(line.spans.len(), 3);
    }

    #[test]
    fn test_ansi_render_with_annotation() {
        let renderer = AnsiHexRenderer::new(HexViewConfig::default());
        let ann = Annotation {
            offset: 0,
            len: 2,
            label: "test".to_string(),
            color: Color::red(),
        };
        let data = [0x01, 0x02, 0x03];
        let line = renderer.render_line(0, &data, &[ann]);
        assert_eq!(line.spans[0].fg, Color::red());
        assert_eq!(line.spans[1].fg, Color::red());
    }

    // ── AnnotationLayer ───────────────────────────────────────────────────────

    #[test]
    fn test_annotation_layer_add_sorted() {
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation {
            offset: 10,
            len: 5,
            label: "b".to_string(),
            color: Color::red(),
        });
        layer.add(Annotation {
            offset: 0,
            len: 3,
            label: "a".to_string(),
            color: Color::green(),
        });
        assert_eq!(layer.annotations[0].offset, 0);
    }

    #[test]
    fn test_annotation_overlapping() {
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation {
            offset: 0,
            len: 10,
            label: "big".to_string(),
            color: Color::red(),
        });
        layer.add(Annotation {
            offset: 20,
            len: 5,
            label: "other".to_string(),
            color: Color::blue(),
        });
        let hits = layer.overlapping(5, 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].label, "big");
    }

    #[test]
    fn test_annotation_no_overlap() {
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation {
            offset: 0,
            len: 5,
            label: "a".to_string(),
            color: Color::red(),
        });
        layer.add(Annotation {
            offset: 10,
            len: 5,
            label: "b".to_string(),
            color: Color::blue(),
        });
        assert!(!layer.has_overlap());
    }

    #[test]
    fn test_annotation_merge() {
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation {
            offset: 0,
            len: 10,
            label: "a".to_string(),
            color: Color::red(),
        });
        layer.add(Annotation {
            offset: 8,
            len: 5,
            label: "b".to_string(),
            color: Color::blue(),
        });
        assert!(layer.has_overlap());
        layer.merge_overlapping();
        assert_eq!(layer.annotations.len(), 1);
        assert_eq!(layer.annotations[0].len, 13);
    }

    #[test]
    fn test_annotation_len_is_empty() {
        let mut layer = AnnotationLayer::new();
        assert!(layer.is_empty());
        assert_eq!(layer.len(), 0);
        layer.add(Annotation {
            offset: 0,
            len: 1,
            label: "x".to_string(),
            color: Color::red(),
        });
        assert!(!layer.is_empty());
        assert_eq!(layer.len(), 1);
    }

    #[test]
    fn test_floating_annotation() {
        let mut layer = AnnotationLayer::new();
        layer.add_floating(FloatingAnnotation::new(5, "note", Color::cyan(), true));
        assert_eq!(layer.floating_at(5).len(), 1);
        assert_eq!(layer.floating_at(6).len(), 0);
    }

    // ── DiffHighlightMap ──────────────────────────────────────────────────────

    #[test]
    fn test_diff_highlight_no_changes() {
        let dm = DiffHighlightMap::default();
        assert!(!dm.has_changes());
        assert_eq!(dm.status(0), DiffStatus::Same);
    }

    #[test]
    fn test_diff_highlight_from_regions() {
        use rustre_hex::DiffRegion;
        let regions = vec![DiffRegion {
            offset: 1,
            len: 2,
            left: vec![0xAA, 0xBB],
            right: vec![0xCC, 0xDD],
        }];
        let dm = DiffHighlightMap::from_diff_regions(&regions, 4);
        assert!(dm.has_changes());
        assert_eq!(dm.status(0), DiffStatus::Same);
        assert_eq!(dm.status(1), DiffStatus::Changed);
        assert_eq!(dm.status(2), DiffStatus::Changed);
    }

    // ── StructureOverlayView ──────────────────────────────────────────────────

    #[test]
    fn test_structure_overlay_at_offset() {
        let mut ov = StructureOverlayView::new();
        ov.add(StructFieldOverlay::new(
            0,
            4,
            "Magic",
            "u32",
            Color::yellow(),
        ));
        ov.add(StructFieldOverlay::new(
            4,
            2,
            "Machine",
            "u16",
            Color::cyan(),
        ));
        assert_eq!(ov.at_offset(0).len(), 1);
        assert_eq!(ov.at_offset(3).len(), 1);
        assert_eq!(ov.at_offset(4).len(), 1);
        assert_eq!(ov.at_offset(6).len(), 0);
    }

    // ── HexViewState navigation ───────────────────────────────────────────────

    #[test]
    fn test_go_to_offset() {
        let mut state = HexViewState::new(test_buf());
        state.go_to_offset(0x10);
        assert_eq!(state.viewport.cursor, 0x10);
    }

    #[test]
    fn test_cursor_move_right() {
        let mut state = HexViewState::new(test_buf());
        state.cursor_move_right();
        assert_eq!(state.viewport.cursor, 1);
    }

    #[test]
    fn test_cursor_move_left_clamps() {
        let mut state = HexViewState::new(test_buf());
        state.cursor_move_left();
        assert_eq!(state.viewport.cursor, 0);
    }

    #[test]
    fn test_cursor_move_up_clamps() {
        let mut state = HexViewState::new(test_buf());
        state.cursor_move_up();
        assert_eq!(state.viewport.cursor, 0);
    }

    #[test]
    fn test_cursor_move_down() {
        let mut state = HexViewState::new(test_buf());
        state.cursor_move_down();
        assert_eq!(state.viewport.cursor, 16);
    }

    #[test]
    fn test_page_down() {
        let buf = HexBuffer::new(vec![0u8; 1024]);
        let mut state = HexViewState::new(buf);
        state.page_down();
        assert!(state.viewport.cursor > 0 || state.viewport.top_offset > 0);
    }

    #[test]
    fn test_page_up_at_top() {
        let mut state = HexViewState::new(test_buf());
        state.page_up();
        assert_eq!(state.viewport.top_offset, 0);
    }

    #[test]
    fn test_scroll_to_aligns_row() {
        let mut state = HexViewState::new(test_buf());
        state.scroll_to(17);
        assert_eq!(state.viewport.top_offset, 16);
    }

    #[test]
    fn test_go_to_start_end() {
        let mut state = HexViewState::new(test_buf());
        state.go_to_offset(100);
        state.go_to_start();
        assert_eq!(state.viewport.cursor, 0);
        state.go_to_end();
        assert_eq!(state.viewport.cursor, 255);
    }

    #[test]
    fn test_selection() {
        let mut state = HexViewState::new(test_buf());
        state.go_to_offset(5);
        state.begin_selection();
        state.go_to_offset(10);
        state.extend_selection();
        let sel = state.selected_bytes().unwrap();
        assert_eq!(sel.len(), 6);
        state.clear_selection();
        assert!(state.viewport.selection.is_none());
    }

    #[test]
    fn test_total_rows() {
        let buf = HexBuffer::new(vec![0u8; 32]);
        let state = HexViewState::new(buf);
        assert_eq!(state.total_rows(), 2);
    }

    #[test]
    fn test_diff_mode() {
        let buf_a = HexBuffer::new(vec![1, 2, 3, 4]);
        let buf_b = HexBuffer::new(vec![1, 9, 3, 4]);
        let mut state = HexViewState::new(buf_a);
        state.set_diff_buffer(buf_b);
        assert!(state.config.show_diff);
        assert!(state.diff_highlights.has_changes());
        state.clear_diff();
        assert!(!state.config.show_diff);
    }

    // ── format_hex_dump ───────────────────────────────────────────────────────

    #[test]
    fn test_format_hex_dump_basic() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let dump = format_hex_dump(&data, 0);
        assert!(dump.contains("DE"));
        assert!(dump.contains("EF"));
    }

    #[test]
    fn test_format_hex_dump_offset() {
        let data = [0xAAu8; 4];
        let dump = format_hex_dump(&data, 0x1000);
        assert!(dump.contains("00001000"));
    }

    #[test]
    fn test_format_hex_dump_multiline() {
        let data = [0u8; 32];
        let dump = format_hex_dump(&data, 0);
        assert_eq!(dump.lines().count(), 2);
    }

    // ── ColorScheme ───────────────────────────────────────────────────────────

    #[test]
    fn test_all_color_schemes_have_map() {
        for scheme in [
            ColorScheme::Dark,
            ColorScheme::Light,
            ColorScheme::Monokai,
            ColorScheme::Nord,
            ColorScheme::Solarized,
            ColorScheme::HighContrast,
        ] {
            let cm = scheme.color_map();
            assert!(!cm.ranges.is_empty(), "{} has no ranges", scheme.name());
        }
    }

    #[test]
    fn test_all_color_schemes_names() {
        assert_eq!(ColorScheme::Dark.name(), "Dark");
        assert_eq!(ColorScheme::Solarized.name(), "Solarized");
    }

    // ── render_all ────────────────────────────────────────────────────────────

    #[test]
    fn test_render_all_row_count() {
        let renderer = PlainHexRenderer::new(HexViewConfig::default());
        let data = [0u8; 32];
        let layer = AnnotationLayer::new();
        let lines = renderer.render_all(&data, 0, &HexViewConfig::default(), &layer);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_render_all_partial_last_row() {
        let renderer = PlainHexRenderer::new(HexViewConfig::default());
        let data = [0u8; 20];
        let layer = AnnotationLayer::new();
        let lines = renderer.render_all(&data, 0, &HexViewConfig::default(), &layer);
        assert_eq!(lines.len(), 2);
    }

    // ── EntropyBar ────────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_bar_all_filled() {
        let bar = EntropyBar::build(8.0);
        assert_eq!(bar.bar, "########");
    }

    #[test]
    fn test_entropy_bar_all_empty() {
        let bar = EntropyBar::build(0.0);
        assert_eq!(bar.bar, "........");
    }

    #[test]
    fn test_entropy_bar_half() {
        let bar = EntropyBar::build(4.0);
        assert_eq!(bar.bar.chars().filter(|&c| c == '#').count(), 4);
    }

    // ── ViewportState ─────────────────────────────────────────────────────────

    #[test]
    fn test_viewport_is_visible() {
        let vp = ViewportState {
            top_offset: 0,
            cursor: 0,
            selection: None,
        };
        let cfg = HexViewConfig::default();
        assert!(vp.is_visible(0, &cfg));
        assert!(vp.is_visible(16 * 23, &cfg));
        assert!(!vp.is_visible(16 * 25, &cfg));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MiniMap — column-granularity visual overview
// ─────────────────────────────────────────────────────────────────────────────

/// Pixel kind for a `MiniMap` cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiniMapCell {
    /// Null bytes.
    Null,
    /// Printable ASCII.
    Printable,
    /// Control characters.
    Control,
    /// High bytes (0x80–0xFF).
    High,
    /// Currently selected region.
    Selected,
    /// Annotated region.
    Annotated,
}

impl MiniMapCell {
    /// Return an ANSI block character representing the cell type.
    #[must_use]
    pub const fn ansi_char(self) -> char {
        match self {
            Self::Null => ' ',
            Self::Printable => '░',
            Self::Control => '▒',
            Self::High => '▓',
            Self::Selected => '█',
            Self::Annotated => '▪',
        }
    }

    /// Returns `true` if this cell represents meaningful data.
    #[must_use]
    pub const fn is_data(self) -> bool {
        !matches!(self, Self::Null)
    }
}

/// Compact overview of an entire buffer at reduced resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniMap {
    /// Cells in row-major order.
    pub cells: Vec<MiniMapCell>,
    /// Number of cells per row.
    pub width: usize,
    /// Number of rows.
    pub height: usize,
    /// Number of bytes represented by each cell.
    pub bytes_per_cell: usize,
}

impl MiniMap {
    /// Build a `MiniMap` from a byte slice.
    ///
    /// `width` × `height` cells; each cell covers `data.len() / (width * height)` bytes.
    ///
    /// # Panics
    /// Panics if `width` or `height` is zero.
    #[must_use]
    pub fn build(
        data: &[u8],
        width: usize,
        height: usize,
        selection: Option<Range<usize>>,
        annotations: &[Range<usize>],
    ) -> Self {
        assert!(
            width > 0 && height > 0,
            "MiniMap: width and height must be > 0"
        );
        let total_cells = width * height;
        let bytes_per_cell = data.len().max(1).div_ceil(total_cells);
        let mut cells = Vec::with_capacity(total_cells);

        for i in 0..total_cells {
            let start = i * bytes_per_cell;
            let end = ((i + 1) * bytes_per_cell).min(data.len());
            let byte_range = start..end;

            // Determine if this cell overlaps selection or annotations.
            let in_selection = selection
                .as_ref()
                .is_some_and(|s| s.start < end && start < s.end);
            let in_annotation = annotations.iter().any(|a| a.start < end && start < a.end);

            let cell = if in_selection {
                MiniMapCell::Selected
            } else if in_annotation {
                MiniMapCell::Annotated
            } else if byte_range.is_empty() {
                MiniMapCell::Null
            } else {
                // Classify by majority byte kind.
                let mut nulls = 0u32;
                let mut printable = 0u32;
                let mut control = 0u32;
                let mut high = 0u32;
                for &b in &data[byte_range] {
                    match b {
                        0 => nulls += 1,
                        32..=126 => printable += 1,
                        1..=31 | 127 => control += 1,
                        _ => high += 1,
                    }
                }
                let max = nulls.max(printable).max(control).max(high);
                if max == nulls {
                    MiniMapCell::Null
                } else if max == printable {
                    MiniMapCell::Printable
                } else if max == control {
                    MiniMapCell::Control
                } else {
                    MiniMapCell::High
                }
            };
            cells.push(cell);
        }

        Self {
            cells,
            width,
            height,
            bytes_per_cell,
        }
    }

    /// Render the `MiniMap` to a multi-line ANSI string.
    #[must_use]
    pub fn render_ansi(&self) -> String {
        let mut out = String::new();
        for row in 0..self.height {
            for col in 0..self.width {
                let idx = row * self.width + col;
                if idx < self.cells.len() {
                    out.push(self.cells[idx].ansi_char());
                }
            }
            out.push('\n');
        }
        out
    }

    /// Cell at (row, col). Returns `None` for out-of-bounds.
    #[must_use]
    pub fn cell_at(&self, row: usize, col: usize) -> Option<MiniMapCell> {
        let idx = row * self.width + col;
        self.cells.get(idx).copied()
    }

    /// Convert a cell index to the byte offset it represents.
    #[must_use]
    pub const fn cell_to_offset(&self, idx: usize) -> usize {
        idx * self.bytes_per_cell
    }

    /// Convert a byte offset to the cell index that covers it.
    #[must_use]
    pub const fn offset_to_cell(&self, offset: usize) -> usize {
        if self.bytes_per_cell == 0 {
            return 0;
        }
        offset / self.bytes_per_cell
    }

    /// Number of cells.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.cells.len()
    }

    /// Returns `true` if there are no cells.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RulerStyle — line numbering styles
// ─────────────────────────────────────────────────────────────────────────────

/// Which base to use for offset ruler labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RulerBase {
    Hex,
    Dec,
    Oct,
}

impl RulerBase {
    /// Format an offset value.
    #[must_use]
    pub fn format(self, offset: usize, width: usize) -> String {
        match self {
            Self::Hex => format!("{offset:0>width$X}"),
            Self::Dec => format!("{offset:0>width$}"),
            Self::Oct => format!("{offset:0>width$o}"),
        }
    }
}

/// Ruler label for a given row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulerLabel {
    /// Byte offset.
    pub offset: usize,
    /// Formatted string.
    pub label: String,
}

/// Build ruler labels for all rows covering `data_len` bytes.
///
/// # Panics
/// Panics if `columns` is zero.
#[must_use]
pub fn build_ruler(
    data_len: usize,
    columns: usize,
    base: RulerBase,
    label_width: usize,
) -> Vec<RulerLabel> {
    assert!(columns > 0, "build_ruler: columns must be > 0");
    let mut labels = Vec::new();
    let mut offset = 0;
    while offset < data_len || (offset == 0 && data_len == 0) {
        labels.push(RulerLabel {
            offset,
            label: base.format(offset, label_width),
        });
        if data_len == 0 {
            break;
        }
        offset += columns;
    }
    labels
}

// ─────────────────────────────────────────────────────────────────────────────
// ColumnHeader — hex column header row
// ─────────────────────────────────────────────────────────────────────────────

/// Generate the hex column header string for a given number of columns.
///
/// Example output for columns=16: `"00 01 02 … 0F"`.
///
/// # Panics
/// Panics if `columns` is zero.
#[must_use]
pub fn build_column_header(columns: usize) -> String {
    assert!(columns > 0, "build_column_header: columns must be > 0");
    let parts: Vec<String> = (0..columns).map(|i| format!("{i:02X}")).collect();
    parts.join(" ")
}

// ─────────────────────────────────────────────────────────────────────────────
// HexSearchHighlight — highlight search results in a rendered view
// ─────────────────────────────────────────────────────────────────────────────

/// A single search-result highlight span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHighlight {
    /// Start byte offset.
    pub start: usize,
    /// Length in bytes.
    pub len: usize,
    /// Whether this is the currently focused result.
    pub is_focused: bool,
}

impl SearchHighlight {
    /// Create a new highlight.
    #[must_use]
    pub const fn new(start: usize, len: usize) -> Self {
        Self {
            start,
            len,
            is_focused: false,
        }
    }

    /// Mark as focused (current match).
    #[must_use]
    pub const fn focused(mut self) -> Self {
        self.is_focused = true;
        self
    }

    /// End byte offset (exclusive).
    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.len
    }

    /// Returns `true` if `offset` is within this highlight.
    #[must_use]
    pub const fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end()
    }
}

/// A collection of search highlights for a rendered view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchHighlightLayer {
    highlights: Vec<SearchHighlight>,
    /// Index of the currently focused highlight.
    pub focused_index: Option<usize>,
}

impl SearchHighlightLayer {
    /// Create an empty layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a list of match offsets and lengths.
    #[must_use]
    pub fn from_matches(matches: &[(usize, usize)]) -> Self {
        let highlights = matches
            .iter()
            .map(|&(s, l)| SearchHighlight::new(s, l))
            .collect();
        Self {
            highlights,
            focused_index: None,
        }
    }

    /// Set the focused index.
    pub const fn set_focus(&mut self, idx: usize) {
        if idx < self.highlights.len() {
            self.focused_index = Some(idx);
        }
    }

    /// Advance focus to next match.
    pub fn focus_next(&mut self) {
        if self.highlights.is_empty() {
            return;
        }
        let next = self
            .focused_index
            .map_or(0, |i| (i + 1) % self.highlights.len());
        self.focused_index = Some(next);
    }

    /// Retreat focus to previous match.
    pub fn focus_prev(&mut self) {
        if self.highlights.is_empty() {
            return;
        }
        let prev = self
            .focused_index
            .map_or(0, |i| {
                if i == 0 {
                    self.highlights.len() - 1
                } else {
                    i - 1
                }
            });
        self.focused_index = Some(prev);
    }

    /// Get all highlights at an offset.
    #[must_use]
    pub fn at_offset(&self, offset: usize) -> Vec<&SearchHighlight> {
        self.highlights
            .iter()
            .filter(|h| h.contains(offset))
            .collect()
    }

    /// Number of highlights.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.highlights.len()
    }

    /// Returns `true` if there are no highlights.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.highlights.is_empty()
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
        self.focused_index = None;
    }

    /// Currently focused highlight.
    #[must_use]
    pub fn focused(&self) -> Option<&SearchHighlight> {
        self.focused_index.and_then(|i| self.highlights.get(i))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BookmarkView — rendered bookmark layer
// ─────────────────────────────────────────────────────────────────────────────

/// A bookmark entry for view rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntry {
    /// Byte offset.
    pub offset: usize,
    /// Display name.
    pub name: String,
    /// Optional colour.
    pub color: Option<Color>,
}

impl BookmarkEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(offset: usize, name: impl Into<String>) -> Self {
        Self {
            offset,
            name: name.into(),
            color: None,
        }
    }

    /// Attach a colour.
    #[must_use]
    pub const fn with_color(mut self, c: Color) -> Self {
        self.color = Some(c);
        self
    }
}

/// Ordered list of view bookmarks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BookmarkView {
    entries: Vec<BookmarkEntry>,
}

impl BookmarkView {
    /// Create empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add(&mut self, entry: BookmarkEntry) {
        self.entries.push(entry);
        self.entries.sort_by_key(|e| e.offset);
    }

    /// Remove by name. Returns `true` if found.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < before
    }

    /// Find entries near `offset` (within `tolerance` bytes).
    #[must_use]
    pub fn near(&self, offset: usize, tolerance: usize) -> Vec<&BookmarkEntry> {
        self.entries
            .iter()
            .filter(|e| e.offset.abs_diff(offset) <= tolerance)
            .collect()
    }

    /// All entries.
    #[must_use]
    pub fn all(&self) -> &[BookmarkEntry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Import from `rustre_hex::Bookmark` list.
    #[must_use]
    pub fn from_hex_bookmarks(bookmarks: &[Bookmark]) -> Self {
        let entries = bookmarks
            .iter()
            .map(|b| BookmarkEntry::new(b.offset, b.name.clone()))
            .collect();
        Self { entries }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SelectionStats — statistics about a selection
// ─────────────────────────────────────────────────────────────────────────────

/// Byte statistics for the current selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionStats {
    /// Length in bytes.
    pub len: usize,
    /// Sum of all bytes.
    pub sum: u64,
    /// Minimum byte value.
    pub min: u8,
    /// Maximum byte value.
    pub max: u8,
    /// Mean byte value.
    pub mean: f64,
    /// Shannon entropy.
    pub entropy: f64,
    /// Number of distinct byte values.
    pub distinct: usize,
    /// Most common byte value and its count.
    pub mode: (u8, u64),
}

impl SelectionStats {
    /// Compute statistics from a byte slice.
    ///
    /// Returns `None` if `data` is empty.
    #[must_use]
    pub fn compute(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let mut counts = [0u64; 256];
        let mut sum = 0u64;
        for &b in data {
            counts[b as usize] += 1;
            sum += u64::from(b);
        }
        let min = data.iter().copied().min().unwrap_or(0);
        let max = data.iter().copied().max().unwrap_or(0);
        let mean = sum as f64 / data.len() as f64;
        let total = data.len() as f64;
        let entropy = counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / total;
                -p * p.log2()
            })
            .sum();
        let distinct = counts.iter().filter(|&&c| c > 0).count();
        let (mode_idx, &mode_cnt) = counts
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| *c)
            .unwrap_or((0, &0));
        Some(Self {
            len: data.len(),
            sum,
            min,
            max,
            mean,
            entropy,
            distinct,
            mode: (mode_idx as u8, mode_cnt),
        })
    }

    /// Format as a concise status-bar string.
    #[must_use]
    pub fn status_line(&self) -> String {
        format!(
            "Sel: {} bytes  Sum: {}  Min: 0x{:02X}  Max: 0x{:02X}  Mean: {:.1}  Entropy: {:.3}  Distinct: {}",
            self.len, self.sum, self.min, self.max, self.mean, self.entropy, self.distinct
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexFindBar — model for a "find" input bar
// ─────────────────────────────────────────────────────────────────────────────

/// Input mode for the find bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindBarMode {
    /// Plain hex bytes (e.g. `DE AD BE EF`).
    HexBytes,
    /// ASCII text literal.
    AsciiText,
    /// Regex over bytes.
    Regex,
}

/// State of the find-bar widget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexFindBar {
    /// Current search query text.
    pub query: String,
    /// Which mode to interpret the query as.
    pub mode: FindBarMode,
    /// Whether case sensitivity is enabled (for ASCII/Regex).
    pub case_sensitive: bool,
    /// Whether wrap-around search is enabled.
    pub wrap: bool,
    /// Current match count (0 = not yet searched).
    pub match_count: usize,
    /// Current focused match index (0-based).
    pub focused_match: Option<usize>,
    /// Whether the bar is visible.
    pub visible: bool,
}

impl HexFindBar {
    /// Create a new find bar in its default state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            query: String::new(),
            mode: FindBarMode::HexBytes,
            case_sensitive: false,
            wrap: true,
            match_count: 0,
            focused_match: None,
            visible: false,
        }
    }

    /// Open the find bar with focus.
    pub const fn open(&mut self) {
        self.visible = true;
    }

    /// Close and reset the find bar.
    pub const fn close(&mut self) {
        self.visible = false;
        self.match_count = 0;
        self.focused_match = None;
    }

    /// Update the query string.
    pub fn set_query(&mut self, q: impl Into<String>) {
        self.query = q.into();
        self.match_count = 0;
        self.focused_match = None;
    }

    /// Record search results.
    pub const fn set_results(&mut self, count: usize) {
        self.match_count = count;
        self.focused_match = if count > 0 { Some(0) } else { None };
    }

    /// Advance to next match.
    pub const fn next_match(&mut self) {
        if self.match_count == 0 {
            return;
        }
        self.focused_match = Some(match self.focused_match {
            Some(i) => {
                if i + 1 < self.match_count {
                    i + 1
                } else if self.wrap {
                    0
                } else {
                    i
                }
            }
            None => 0,
        });
    }

    /// Retreat to previous match.
    pub const fn prev_match(&mut self) {
        if self.match_count == 0 {
            return;
        }
        self.focused_match = Some(match self.focused_match {
            Some(0) => {
                if self.wrap {
                    self.match_count - 1
                } else {
                    0
                }
            }
            Some(i) => i - 1,
            None => 0,
        });
    }

    /// Status text for display (e.g. "3 / 12").
    #[must_use]
    pub fn status_text(&self) -> String {
        match self.focused_match {
            Some(i) => format!("{} / {}", i + 1, self.match_count),
            None if self.match_count == 0 => "No results".to_owned(),
            None => format!("{} results", self.match_count),
        }
    }
}

impl Default for HexFindBar {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PaletteHighlight — per-byte colour assignment from palette
// ─────────────────────────────────────────────────────────────────────────────

/// A palette highlight maps byte offsets to colours derived from byte values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaletteHighlight {
    /// Which colour scheme to apply.
    pub scheme: ColorScheme,
    /// Maximum number of bytes to colourise (for large buffer performance).
    pub max_bytes: usize,
}

impl PaletteHighlight {
    /// Default palette highlight with `max_bytes = 65536`.
    #[must_use]
    pub const fn new(scheme: ColorScheme) -> Self {
        Self {
            scheme,
            max_bytes: 65536,
        }
    }

    /// Assign a `ColorSpan` for each byte in `data[..max_bytes]`.
    #[must_use]
    pub fn spans(&self, data: &[u8]) -> Vec<ColorSpan> {
        let cm = self.scheme.color_map();
        let limit = self.max_bytes.min(data.len());
        data[..limit]
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let (fg, bg) = cm.lookup(b);
                ColorSpan {
                    start: i,
                    end: i + 1,
                    fg,
                    bg,
                    bold: false,
                    underline: false,
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexStatusBar — model for the status bar
// ─────────────────────────────────────────────────────────────────────────────

/// Status-bar information extracted from the view state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexStatusBar {
    /// Current cursor offset (decimal).
    pub offset_dec: usize,
    /// Current cursor offset (hex).
    pub offset_hex: String,
    /// Byte value at cursor (if any).
    pub byte_value: Option<u8>,
    /// Byte value as signed integer.
    pub byte_signed: Option<i8>,
    /// Buffer size.
    pub buffer_size: usize,
    /// Selection start and end (inclusive) if any.
    pub selection: Option<(usize, usize)>,
    /// Current colour scheme name.
    pub scheme_name: String,
}

impl HexStatusBar {
    /// Build from a `HexViewState`.
    #[must_use]
    pub fn from_state(state: &HexViewState) -> Self {
        let offset = state.viewport.cursor;
        let byte_value = state.buffer.data.get(offset).copied();
        let byte_signed = byte_value.map(|b| b as i8);
        let selection = state
            .viewport
            .selection
            .as_ref()
            .map(|r| (r.start, r.end.saturating_sub(1)));
        Self {
            offset_dec: offset,
            offset_hex: format!("{offset:08X}"),
            byte_value,
            byte_signed,
            buffer_size: state.buffer.data.len(),
            selection,
            scheme_name: state.config.color_scheme.name().to_owned(),
        }
    }

    /// Build a single-line status string.
    #[must_use]
    pub fn render(&self) -> String {
        let byte_str = match self.byte_value {
            Some(b) => format!("0x{:02X} ({}) ({}i8)", b, b, self.byte_signed.unwrap_or(0)),
            None => "\u{2014}".to_owned(),
        };
        let sel_str = match self.selection {
            Some((s, e)) => format!("  Sel: {s}\u{2013}{e} ({} bytes)", e - s + 1),
            None => String::new(),
        };
        format!(
            "Offset: {} (0x{})  Byte: {}  Size: {}{}",
            self.offset_dec, self.offset_hex, byte_str, self.buffer_size, sel_str
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RowMetrics — metrics for a rendered row
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics about a rendered hex row — used for hit-testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowMetrics {
    /// Byte offset of the first byte on this row.
    pub row_offset: usize,
    /// Number of bytes on this row.
    pub byte_count: usize,
    /// Pixel/character column of the first hex byte.
    pub hex_start_col: usize,
    /// Pixel/character column of the ASCII section start.
    pub ascii_start_col: usize,
    /// Total rendered width.
    pub total_width: usize,
}

impl RowMetrics {
    /// Compute column metrics for a row given a config.
    #[must_use]
    pub const fn compute(row_offset: usize, byte_count: usize, config: &HexViewConfig) -> Self {
        // offset label width: 8 hex digits + "  " = 10
        let hex_start_col = 10;
        // each byte is "XX " = 3 chars, except last which is "XX"
        let hex_width = byte_count * 3;
        let ascii_start_col = hex_start_col + hex_width + 1;
        let total_width = ascii_start_col + byte_count + 2; // " |" + ascii + "|"
        let _ = config; // reserved for future use
        Self {
            row_offset,
            byte_count,
            hex_start_col,
            ascii_start_col,
            total_width,
        }
    }

    /// Determine which byte offset a column corresponds to.
    ///
    /// Returns `None` if the column is in the offset label or separator.
    #[must_use]
    pub const fn col_to_offset(&self, col: usize) -> Option<usize> {
        if col >= self.hex_start_col && col < self.ascii_start_col {
            let rel = col - self.hex_start_col;
            let byte_idx = rel / 3;
            if byte_idx < self.byte_count {
                Some(self.row_offset + byte_idx)
            } else {
                None
            }
        } else if col >= self.ascii_start_col && col < self.ascii_start_col + self.byte_count {
            Some(self.row_offset + col - self.ascii_start_col)
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_ext {
    use super::*;

    fn make_data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 256) as u8).collect()
    }

    // ── MiniMap ───────────────────────────────────────────────────────────────

    #[test]
    fn test_minimap_build_basic() {
        let data: Vec<u8> = (0u8..=255).collect();
        let mm = MiniMap::build(&data, 16, 16, None, &[]);
        assert_eq!(mm.len(), 256);
        assert_eq!(mm.width, 16);
        assert_eq!(mm.height, 16);
    }

    #[test]
    fn test_minimap_render_ansi_newlines() {
        let data = vec![0x41u8; 64];
        let mm = MiniMap::build(&data, 8, 4, None, &[]);
        let rendered = mm.render_ansi();
        assert_eq!(rendered.lines().count(), 4);
    }

    #[test]
    fn test_minimap_selection_cell() {
        let data = vec![0x41u8; 16];
        let mm = MiniMap::build(&data, 4, 4, Some(0..4), &[]);
        assert_eq!(mm.cells[0], MiniMapCell::Selected);
    }

    #[test]
    fn test_minimap_annotation_cell() {
        let data = vec![0x41u8; 16];
        let mm = MiniMap::build(&data, 4, 4, None, &[8..12]);
        // cells[8..12] should be Annotated (bytes_per_cell = 1 for 16 bytes / 16 cells)
        assert_eq!(mm.cells[8], MiniMapCell::Annotated);
        assert_eq!(mm.cells[11], MiniMapCell::Annotated);
        // cells outside annotation range should be Printable
        assert_ne!(mm.cells[0], MiniMapCell::Annotated);
    }

    #[test]
    fn test_minimap_null_cell() {
        let data = vec![0u8; 16];
        let mm = MiniMap::build(&data, 4, 4, None, &[]);
        assert!(mm.cells.iter().all(|c| *c == MiniMapCell::Null));
    }

    #[test]
    fn test_minimap_cell_ansi_chars() {
        assert_eq!(MiniMapCell::Null.ansi_char(), ' ');
        assert_eq!(MiniMapCell::Printable.ansi_char(), '░');
        assert_eq!(MiniMapCell::Selected.ansi_char(), '█');
    }

    #[test]
    fn test_minimap_offset_roundtrip() {
        let data = make_data(256);
        let mm = MiniMap::build(&data, 16, 16, None, &[]);
        let idx = mm.offset_to_cell(128);
        let back = mm.cell_to_offset(idx);
        assert!(back <= 128 && back + mm.bytes_per_cell > 128);
    }

    // ── RulerBase ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ruler_hex() {
        assert_eq!(RulerBase::Hex.format(255, 4), "00FF");
    }

    #[test]
    fn test_ruler_dec() {
        assert_eq!(RulerBase::Dec.format(42, 5), "00042");
    }

    #[test]
    fn test_ruler_oct() {
        assert_eq!(RulerBase::Oct.format(8, 4), "0010");
    }

    #[test]
    fn test_build_ruler_count() {
        let labels = build_ruler(64, 16, RulerBase::Hex, 8);
        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0].offset, 0);
        assert_eq!(labels[1].offset, 16);
    }

    #[test]
    fn test_build_ruler_empty() {
        let labels = build_ruler(0, 16, RulerBase::Hex, 8);
        assert_eq!(labels.len(), 1); // one label at offset 0
        assert_eq!(labels[0].offset, 0);
    }

    // ── ColumnHeader ──────────────────────────────────────────────────────────

    #[test]
    fn test_column_header_16() {
        let h = build_column_header(16);
        assert!(h.starts_with("00 01"));
        assert!(h.ends_with("0F"));
        assert_eq!(h.split_whitespace().count(), 16);
    }

    #[test]
    fn test_column_header_4() {
        let h = build_column_header(4);
        assert_eq!(h, "00 01 02 03");
    }

    // ── SearchHighlightLayer ──────────────────────────────────────────────────

    #[test]
    fn test_search_highlight_basic() {
        let mut layer = SearchHighlightLayer::from_matches(&[(0, 4), (10, 4)]);
        assert_eq!(layer.len(), 2);
        assert_eq!(layer.at_offset(2).len(), 1);
        assert_eq!(layer.at_offset(5).len(), 0);
        layer.set_focus(1);
        assert_eq!(layer.focused().unwrap().start, 10);
    }

    #[test]
    fn test_search_highlight_focus_next() {
        let mut layer = SearchHighlightLayer::from_matches(&[(0, 1), (5, 1), (10, 1)]);
        layer.set_focus(0);
        layer.focus_next();
        assert_eq!(layer.focused_index, Some(1));
        layer.focus_next();
        layer.focus_next(); // wraps
        assert_eq!(layer.focused_index, Some(0));
    }

    #[test]
    fn test_search_highlight_contains() {
        let h = SearchHighlight::new(10, 5);
        assert!(h.contains(10));
        assert!(h.contains(14));
        assert!(!h.contains(15));
    }

    #[test]
    fn test_search_highlight_clear() {
        let mut layer = SearchHighlightLayer::from_matches(&[(0, 4)]);
        layer.clear();
        assert!(layer.is_empty());
    }

    // ── BookmarkView ──────────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_view_add_sorted() {
        let mut bv = BookmarkView::new();
        bv.add(BookmarkEntry::new(100, "z"));
        bv.add(BookmarkEntry::new(10, "a"));
        assert_eq!(bv.all()[0].offset, 10);
    }

    #[test]
    fn test_bookmark_view_remove() {
        let mut bv = BookmarkView::new();
        bv.add(BookmarkEntry::new(0, "first"));
        assert!(bv.remove("first"));
        assert!(bv.is_empty());
    }

    #[test]
    fn test_bookmark_view_near() {
        let mut bv = BookmarkView::new();
        bv.add(BookmarkEntry::new(100, "a"));
        bv.add(BookmarkEntry::new(200, "b"));
        let near = bv.near(102, 5);
        assert_eq!(near.len(), 1);
        assert_eq!(near[0].name, "a");
    }

    #[test]
    fn test_bookmark_view_from_hex_bookmarks() {
        let bk = vec![Bookmark {
            name: "ep".to_owned(),
            offset: 0x1000,
            color: 0xFF_00_00_00,
        }];
        let bv = BookmarkView::from_hex_bookmarks(&bk);
        assert_eq!(bv.len(), 1);
        assert_eq!(bv.all()[0].offset, 0x1000);
    }

    // ── SelectionStats ────────────────────────────────────────────────────────

    #[test]
    fn test_selection_stats_empty() {
        assert!(SelectionStats::compute(&[]).is_none());
    }

    #[test]
    fn test_selection_stats_single() {
        let stats = SelectionStats::compute(&[0x42]).unwrap();
        assert_eq!(stats.len, 1);
        assert_eq!(stats.min, 0x42);
        assert_eq!(stats.max, 0x42);
        assert_eq!(stats.distinct, 1);
        assert!((stats.entropy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_selection_stats_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let stats = SelectionStats::compute(&data).unwrap();
        assert_eq!(stats.distinct, 256);
        assert!((stats.entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_selection_stats_status_line() {
        let stats = SelectionStats::compute(b"Hello").unwrap();
        let s = stats.status_line();
        assert!(s.contains("5 bytes"));
    }

    // ── HexFindBar ────────────────────────────────────────────────────────────

    #[test]
    fn test_find_bar_open_close() {
        let mut fb = HexFindBar::new();
        fb.open();
        assert!(fb.visible);
        fb.close();
        assert!(!fb.visible);
        assert_eq!(fb.match_count, 0);
    }

    #[test]
    fn test_find_bar_next_prev() {
        let mut fb = HexFindBar::new();
        fb.open();
        fb.set_results(3);
        assert_eq!(fb.focused_match, Some(0));
        fb.next_match();
        assert_eq!(fb.focused_match, Some(1));
        fb.next_match();
        fb.next_match(); // wraps to 0
        assert_eq!(fb.focused_match, Some(0));
        fb.prev_match(); // wraps to 2
        assert_eq!(fb.focused_match, Some(2));
    }

    #[test]
    fn test_find_bar_status_text() {
        let mut fb = HexFindBar::new();
        fb.set_results(5);
        assert_eq!(fb.status_text(), "1 / 5");
        fb.next_match();
        assert_eq!(fb.status_text(), "2 / 5");
    }

    #[test]
    fn test_find_bar_no_results() {
        let mut fb = HexFindBar::new();
        fb.set_results(0);
        assert_eq!(fb.status_text(), "No results");
    }

    // ── RowMetrics ────────────────────────────────────────────────────────────

    #[test]
    fn test_row_metrics_hex_col() {
        let cfg = HexViewConfig::default();
        let m = RowMetrics::compute(0, 16, &cfg);
        // hex_start_col is 10; byte 0 is at col 10
        assert_eq!(m.col_to_offset(10), Some(0));
        assert_eq!(m.col_to_offset(13), Some(1)); // 10 + 3
    }

    #[test]
    fn test_row_metrics_ascii_col() {
        let cfg = HexViewConfig::default();
        let m = RowMetrics::compute(0, 16, &cfg);
        // ASCII section starts after hex section
        let ascii_col = m.ascii_start_col;
        assert_eq!(m.col_to_offset(ascii_col), Some(0));
        assert_eq!(m.col_to_offset(ascii_col + 5), Some(5));
    }

    #[test]
    fn test_row_metrics_out_of_bounds() {
        let cfg = HexViewConfig::default();
        let m = RowMetrics::compute(0, 16, &cfg);
        // Column 0 is in the offset label region
        assert!(m.col_to_offset(0).is_none());
    }

    // ── HexStatusBar ─────────────────────────────────────────────────────────

    #[test]
    fn test_status_bar_render() {
        let buf = HexBuffer::new(vec![0xDEu8; 32]);
        let state = HexViewState::new(buf);
        let sb = HexStatusBar::from_state(&state);
        let s = sb.render();
        assert!(s.contains("Offset:"));
        assert!(s.contains("Byte:"));
    }

    #[test]
    fn test_status_bar_byte_value() {
        let buf = HexBuffer::new(vec![0xABu8, 0xCD]);
        let state = HexViewState::new(buf);
        let sb = HexStatusBar::from_state(&state);
        assert_eq!(sb.byte_value, Some(0xAB));
    }

    // ── PaletteHighlight ──────────────────────────────────────────────────────

    #[test]
    fn test_palette_highlight_span_count() {
        let ph = PaletteHighlight::new(ColorScheme::Dark);
        let data: Vec<u8> = (0..32).collect();
        let spans = ph.spans(&data);
        assert_eq!(spans.len(), 32);
    }

    #[test]
    fn test_palette_highlight_max_bytes() {
        let mut ph = PaletteHighlight::new(ColorScheme::Dark);
        ph.max_bytes = 10;
        let data: Vec<u8> = (0..100).collect();
        let spans = ph.spans(&data);
        assert_eq!(spans.len(), 10);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteGroupView — group bytes visually into N-byte columns
// ─────────────────────────────────────────────────────────────────────────────

/// How many bytes to display in each visual group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupSize {
    /// No grouping — each byte is shown individually.
    None,
    /// Groups of 2 bytes (16-bit words).
    Two,
    /// Groups of 4 bytes (32-bit dwords).
    Four,
    /// Groups of 8 bytes (64-bit qwords).
    Eight,
}

impl GroupSize {
    /// Number of bytes per group.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        match self {
            Self::None => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    /// Group a byte slice into sub-slices of the configured size.
    ///
    /// The last group may be shorter if `data.len()` is not a multiple of the
    /// group size.
    #[must_use]
    pub fn group<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        let sz = self.bytes();
        data.chunks(sz).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexRenderOptions — runtime configuration for the hex renderer
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime rendering options for a hex view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexRenderOptions {
    /// Number of bytes per row.
    pub bytes_per_row: usize,
    /// Number of bytes in each visual group.
    pub group_size: GroupSize,
    /// Show the ASCII/UTF-8 sidebar.
    pub show_ascii: bool,
    /// Show the byte offset column.
    pub show_offsets: bool,
    /// Upper-case hex digits.
    pub uppercase: bool,
    /// Colour scheme.
    pub color_scheme: ColorScheme,
    /// Separate groups with an extra space.
    pub group_separator: bool,
}

impl Default for HexRenderOptions {
    fn default() -> Self {
        Self {
            bytes_per_row: 16,
            group_size: GroupSize::None,
            show_ascii: true,
            show_offsets: true,
            uppercase: false,
            color_scheme: ColorScheme::Dark,
            group_separator: true,
        }
    }
}

impl HexRenderOptions {
    /// Number of visual columns in a hex row (hex digits + separators).
    #[must_use]
    pub const fn hex_columns(&self) -> usize {
        let _ = self.uppercase;
        let per_byte = 2;
        let groups = self.bytes_per_row.div_ceil(self.group_size.bytes());
        let sep = if self.group_separator {
            groups.saturating_sub(1)
        } else {
            0
        };
        per_byte * self.bytes_per_row + (self.bytes_per_row - 1) + sep
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RenderedRow — one rendered hex-view row
// ─────────────────────────────────────────────────────────────────────────────

/// A fully rendered hex-dump row as plain text.
#[derive(Debug, Clone)]
pub struct RenderedRow {
    /// Byte offset of the first byte in this row.
    pub offset: usize,
    /// Offset column text (e.g. `"00001000"`).
    pub offset_text: String,
    /// Hex byte column text.
    pub hex_text: String,
    /// ASCII sidebar text.
    pub ascii_text: String,
}

impl RenderedRow {
    /// Combine all columns into a single display line.
    #[must_use]
    pub fn to_line(&self, opts: &HexRenderOptions) -> String {
        let mut out = String::new();
        if opts.show_offsets {
            out.push_str(&self.offset_text);
            out.push_str("  ");
        }
        out.push_str(&self.hex_text);
        if opts.show_ascii {
            out.push_str("  |");
            out.push_str(&self.ascii_text);
            out.push('|');
        }
        out
    }
}

/// Render a byte slice as a sequence of `RenderedRow` values.
#[must_use]
pub fn render_rows(data: &[u8], start_offset: usize, opts: &HexRenderOptions) -> Vec<RenderedRow> {
    data.chunks(opts.bytes_per_row)
        .enumerate()
        .map(|(i, chunk)| {
            let off = start_offset + i * opts.bytes_per_row;
            let offset_text = format!("{off:08x}");
            let hex_parts: Vec<String> = chunk
                .iter()
                .map(|b| {
                    if opts.uppercase {
                        format!("{b:02X}")
                    } else {
                        format!("{b:02x}")
                    }
                })
                .collect();
            let hex_text = hex_parts.join(" ");
            let ascii_text: String = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            RenderedRow {
                offset: off,
                offset_text,
                hex_text,
                ascii_text,
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffHighlight — colour spans for two-buffer diff visualization
// ─────────────────────────────────────────────────────────────────────────────

/// A diff span indicating how a byte range in the primary buffer compares
/// to the secondary buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    /// Bytes are identical.
    Same,
    /// Bytes differ.
    Changed,
    /// Byte only present in primary (secondary is shorter).
    Added,
}

/// One contiguous span of bytes with a given diff kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSpan {
    pub start: usize,
    pub end: usize,
    pub kind: DiffKind,
}

/// Compute diff spans for `a` vs `b` (byte-level comparison).
#[must_use]
pub fn compute_diff_spans(a: &[u8], b: &[u8]) -> Vec<DiffSpan> {
    if a.is_empty() {
        return Vec::new();
    }
    let mut spans = Vec::new();
    let mut span_start = 0;
    let mut current_kind = if a.len() > b.len() || b.is_empty() {
        if !b.is_empty() && a[0] == b[0] {
            DiffKind::Same
        } else if b.is_empty() {
            DiffKind::Added
        } else {
            DiffKind::Changed
        }
    } else if a[0] == b[0] {
        DiffKind::Same
    } else {
        DiffKind::Changed
    };

    for i in 0..a.len() {
        let kind = if i >= b.len() {
            DiffKind::Added
        } else if a[i] == b[i] {
            DiffKind::Same
        } else {
            DiffKind::Changed
        };
        if kind != current_kind {
            spans.push(DiffSpan {
                start: span_start,
                end: i,
                kind: current_kind,
            });
            span_start = i;
            current_kind = kind;
        }
    }
    spans.push(DiffSpan {
        start: span_start,
        end: a.len(),
        kind: current_kind,
    });
    spans
}

/// Color to apply to a diff span.
#[must_use]
pub fn diff_span_color(kind: DiffKind, scheme: ColorScheme) -> Color {
    match kind {
        DiffKind::Same => Color::new(100, 100, 100),
        DiffKind::Changed => match scheme {
            ColorScheme::Light => Color::new(180, 40, 40),
            ColorScheme::HighContrast => Color::new(255, 0, 0),
            _ => Color::new(220, 80, 80),
        },
        DiffKind::Added => match scheme {
            ColorScheme::Light => Color::new(40, 140, 40),
            ColorScheme::HighContrast => Color::new(0, 255, 0),
            _ => Color::new(80, 180, 80),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteClassColorizer — colorize bytes by ASCII class
// ─────────────────────────────────────────────────────────────────────────────

/// Byte value classification for colorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteClass {
    /// Zero byte (0x00).
    Zero,
    /// Printable ASCII (0x20–0x7E).
    PrintableAscii,
    /// ASCII control character (0x01–0x1F, 0x7F).
    Control,
    /// High byte (0x80–0xFF).
    High,
}

impl ByteClass {
    /// Classify a single byte.
    #[must_use]
    pub fn of(b: u8) -> Self {
        if b == 0 {
            Self::Zero
        } else if (0x20..=0x7E).contains(&b) {
            Self::PrintableAscii
        } else if b < 0x80 {
            Self::Control
        } else {
            Self::High
        }
    }

    /// Default color for this class in dark mode.
    #[must_use]
    pub const fn dark_color(&self) -> Color {
        match self {
            Self::Zero => Color::new(60, 60, 60),
            Self::PrintableAscii => Color::new(180, 220, 180),
            Self::Control => Color::new(220, 150, 100),
            Self::High => Color::new(150, 180, 220),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for new hex-view types
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_hexview_extra {
    use super::*;

    // ── GroupSize ────────────────────────────────────────────────────────────

    #[test]
    fn group_size_bytes() {
        assert_eq!(GroupSize::None.bytes(), 1);
        assert_eq!(GroupSize::Two.bytes(), 2);
        assert_eq!(GroupSize::Four.bytes(), 4);
        assert_eq!(GroupSize::Eight.bytes(), 8);
    }

    #[test]
    fn group_size_group_even() {
        let data = vec![0u8; 8];
        let groups = GroupSize::Four.group(&data);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 4);
    }

    #[test]
    fn group_size_group_remainder() {
        let data = vec![0u8; 10];
        let groups = GroupSize::Four.group(&data);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[2].len(), 2);
    }

    // ── HexRenderOptions ────────────────────────────────────────────────────

    #[test]
    fn hex_render_options_defaults() {
        let o = HexRenderOptions::default();
        assert_eq!(o.bytes_per_row, 16);
        assert!(o.show_ascii);
        assert!(o.show_offsets);
    }

    #[test]
    fn hex_columns_default() {
        let o = HexRenderOptions::default();
        assert!(o.hex_columns() > 30);
    }

    // ── render_rows ──────────────────────────────────────────────────────────

    #[test]
    fn render_rows_basic() {
        let data: Vec<u8> = (0..32).collect();
        let opts = HexRenderOptions::default();
        let rows = render_rows(&data, 0, &opts);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].offset, 0);
        assert_eq!(rows[1].offset, 16);
        assert!(rows[0].hex_text.contains("00"));
    }

    #[test]
    fn render_rows_uppercase() {
        let data = vec![0xABu8, 0xCD];
        let opts = HexRenderOptions {
            uppercase: true,
            ..HexRenderOptions::default()
        };
        let rows = render_rows(&data, 0, &opts);
        assert!(rows[0].hex_text.contains("AB"));
    }

    #[test]
    fn render_rows_ascii() {
        let data = b"Hello".to_vec();
        let opts = HexRenderOptions::default();
        let rows = render_rows(&data, 0, &opts);
        assert!(rows[0].ascii_text.contains('H'));
    }

    #[test]
    fn rendered_row_to_line() {
        let row = RenderedRow {
            offset: 0,
            offset_text: "00000000".into(),
            hex_text: "41 42".into(),
            ascii_text: "AB".into(),
        };
        let opts = HexRenderOptions::default();
        let line = row.to_line(&opts);
        assert!(line.contains("00000000"));
        assert!(line.contains("41 42"));
        assert!(line.contains("AB"));
    }

    #[test]
    fn render_rows_non_zero_start() {
        let data = vec![0xFFu8; 16];
        let opts = HexRenderOptions::default();
        let rows = render_rows(&data, 0x100, &opts);
        assert_eq!(rows[0].offset, 0x100);
        assert_eq!(rows[0].offset_text, "00000100");
    }

    // ── compute_diff_spans ───────────────────────────────────────────────────

    #[test]
    fn diff_spans_identical() {
        let a = vec![1u8, 2, 3, 4];
        let spans = compute_diff_spans(&a, &a);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kind, DiffKind::Same);
    }

    #[test]
    fn diff_spans_all_different() {
        let a = vec![1u8, 2];
        let b = vec![3u8, 4];
        let spans = compute_diff_spans(&a, &b);
        assert!(spans.iter().all(|s| s.kind == DiffKind::Changed));
    }

    #[test]
    fn diff_spans_added() {
        let a = vec![1u8, 2, 3];
        let b = vec![1u8];
        let spans = compute_diff_spans(&a, &b);
        
        assert!(spans.iter().any(|s| s.kind == DiffKind::Added));
    }

    #[test]
    fn diff_spans_empty() {
        let spans = compute_diff_spans(&[], &[1, 2]);
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_span_color_changed() {
        let c = diff_span_color(DiffKind::Changed, ColorScheme::Dark);
        assert!(c.r > c.b);
    }

    // ── ByteClass ────────────────────────────────────────────────────────────

    #[test]
    fn byte_class_zero() {
        assert_eq!(ByteClass::of(0), ByteClass::Zero);
    }

    #[test]
    fn byte_class_printable() {
        assert_eq!(ByteClass::of(b'A'), ByteClass::PrintableAscii);
        assert_eq!(ByteClass::of(b' '), ByteClass::PrintableAscii);
    }

    #[test]
    fn byte_class_control() {
        assert_eq!(ByteClass::of(0x01), ByteClass::Control);
        assert_eq!(ByteClass::of(0x1F), ByteClass::Control);
    }

    #[test]
    fn byte_class_high() {
        assert_eq!(ByteClass::of(0x80), ByteClass::High);
        assert_eq!(ByteClass::of(0xFF), ByteClass::High);
    }

    #[test]
    fn byte_class_dark_color_different_classes() {
        let z = ByteClass::Zero.dark_color();
        let p = ByteClass::PrintableAscii.dark_color();
        let c = ByteClass::Control.dark_color();
        let h = ByteClass::High.dark_color();
        // All should be distinct
        assert_ne!(z, p);
        assert_ne!(p, c);
        assert_ne!(c, h);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexViewModel — incremental, row-based view over a shared byte buffer
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::Arc;

/// A single displayable row in the hex view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexRow {
    /// Absolute byte offset of the first byte in this row.
    pub offset: u64,
    /// Raw bytes for this row (up to `bytes_per_row`).
    pub bytes: Vec<u8>,
    /// ASCII representation: printable chars kept, everything else replaced
    /// with `.`.
    pub ascii: String,
    /// Space-separated uppercase hex pairs, e.g. `"41 42 43"`.
    pub hex_str: String,
}

impl HexRow {
    /// Build a `HexRow` from a slice.
    #[must_use]
    fn from_slice(offset: u64, data: &[u8]) -> Self {
        let hex_str = data
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii = data
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        Self {
            offset,
            bytes: data.to_vec(),
            ascii,
            hex_str,
        }
    }
}

/// A lightweight, incremental view model over a shared, append-friendly byte
/// buffer.
///
/// `HexViewModel` does not own the data — it holds an `Arc<Vec<u8>>` so that
/// the underlying buffer can be cheaply shared with the rest of the
/// application.  Row slices are computed on-demand; no caching is performed
/// because `Vec<u8>` access is already O(1).
#[derive(Debug, Clone)]
pub struct HexViewModel {
    data: Arc<Vec<u8>>,
    /// Number of bytes shown per row (default 16).
    pub bytes_per_row: u32,
}

impl HexViewModel {
    /// Create a new view model backed by `data`.
    #[must_use]
    pub const fn new(data: Arc<Vec<u8>>) -> Self {
        Self {
            data,
            bytes_per_row: 16,
        }
    }

    /// Total number of bytes in the underlying buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Total number of rows needed to display all data.
    #[must_use]
    pub fn total_rows(&self) -> u64 {
        let bpr = u64::from(self.bytes_per_row);
        (self.data.len() as u64).div_ceil(bpr)
    }

    /// Return a `Vec<HexRow>` for at most `row_count` rows beginning at
    /// `start_row`.  Rows beyond the end of the buffer are silently omitted.
    #[must_use]
    pub fn visible_range(&self, start_row: u64, row_count: u32) -> Vec<HexRow> {
        let bpr = self.bytes_per_row as usize;
        let data_len = self.data.len();
        let mut rows = Vec::with_capacity(row_count as usize);

        for i in 0..u64::from(row_count) {
            let row_idx = start_row + i;
            let byte_start = row_idx as usize * bpr;
            if byte_start >= data_len {
                break;
            }
            let byte_end = (byte_start + bpr).min(data_len);
            rows.push(HexRow::from_slice(
                byte_start as u64,
                &self.data[byte_start..byte_end],
            ));
        }
        rows
    }

    /// Replace the backing buffer (e.g. after a live-update or reload).
    pub fn update_data(&mut self, data: Arc<Vec<u8>>) {
        self.data = data;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexNavigator — stateful navigation, search, and bookmarks
// ─────────────────────────────────────────────────────────────────────────────

/// A unique bookmark identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BookmarkId(pub u64);

/// A named navigation bookmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavBookmark {
    pub id: BookmarkId,
    pub offset: u64,
    pub name: String,
}

/// Lightweight navigator state returned by `goto_offset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexViewNavState {
    /// The requested (clamped) offset.
    pub offset: u64,
    /// The row index corresponding to this offset (with the current bpr).
    pub row: u64,
    /// The column index within that row.
    pub col: u32,
}

/// Stateful navigator attached to a shared byte buffer.
///
/// Maintains a current cursor position, a forward/backward search state, and
/// a personal bookmark list.  All search methods use simple linear scan so
/// they work on any `&[u8]` without extra dependencies.
#[derive(Debug, Clone)]
pub struct HexNavigator {
    data: Arc<Vec<u8>>,
    /// Bytes per row used for row/column calculations.
    pub bytes_per_row: u32,
    /// Current cursor offset.
    pub cursor: u64,
    bookmarks: Vec<NavBookmark>,
    next_bookmark_id: u64,
    /// Last search pattern for repeat-find.
    last_pattern: Option<Vec<u8>>,
}

impl HexNavigator {
    /// Create a new navigator backed by `data`.
    #[must_use]
    pub const fn new(data: Arc<Vec<u8>>) -> Self {
        Self {
            data,
            bytes_per_row: 16,
            cursor: 0,
            bookmarks: Vec::new(),
            next_bookmark_id: 0,
            last_pattern: None,
        }
    }

    /// Move the cursor to `offset` (clamped to the buffer length).
    /// Returns the resulting navigation state.
    #[must_use]
    pub fn goto_offset(&mut self, offset: u64) -> HexViewNavState {
        let clamped = offset.min(self.data.len().saturating_sub(1) as u64);
        self.cursor = clamped;
        let bpr = u64::from(self.bytes_per_row);
        HexViewNavState {
            offset: clamped,
            row: clamped / bpr,
            col: (clamped % bpr) as u32,
        }
    }

    /// Search forward from the current cursor position for `pattern`.
    ///
    /// The search begins at `cursor` (inclusive) and wraps around to the
    /// start of the buffer if the pattern is not found further forward.
    /// After a successful match the internal cursor is advanced to
    /// `match_offset + 1` so that successive calls step through all
    /// occurrences.  Updates `last_pattern`.  Returns `None` if the data is
    /// empty or shorter than the pattern.
    #[must_use]
    pub fn find_next(&mut self, pattern: &[u8]) -> Option<u64> {
        if pattern.is_empty() || self.data.len() < pattern.len() {
            return None;
        }
        self.last_pattern = Some(pattern.to_vec());
        let pat_len = pattern.len();
        let data_len = self.data.len();
        let search_start = self.cursor as usize;

        // Forward pass from cursor (inclusive) to end.
        for i in search_start..=(data_len - pat_len) {
            if self.data[i..i + pat_len] == *pattern {
                // Advance past this match for the next call.
                self.cursor = (i as u64).saturating_add(1);
                return Some(i as u64);
            }
        }
        // Wrap: search from 0 up to (but not including) search_start so we
        // don't re-return a match that the caller already saw.
        let wrap_end = search_start.min(data_len - pat_len);
        for i in 0..wrap_end {
            if self.data[i..i + pat_len] == *pattern {
                self.cursor = (i as u64).saturating_add(1);
                return Some(i as u64);
            }
        }
        None
    }

    /// Search backward from the current cursor position for `pattern`.
    ///
    /// Wraps around to the end of the buffer.  Updates `last_pattern`.
    #[must_use]
    pub fn find_prev(&mut self, pattern: &[u8]) -> Option<u64> {
        if pattern.is_empty() || self.data.len() < pattern.len() {
            return None;
        }
        self.last_pattern = Some(pattern.to_vec());
        let pat_len = pattern.len();
        let data_len = self.data.len();

        // Backward pass from cursor-1 to 0.
        if self.cursor > 0 {
            let end = ((self.cursor as usize).saturating_sub(1)).min(data_len - pat_len);
            for i in (0..=end).rev() {
                if self.data[i..i + pat_len] == *pattern {
                    self.cursor = i as u64;
                    return Some(i as u64);
                }
            }
        }
        // Wrap: search from the end down to cursor.
        let wrap_start = (self.cursor as usize).min(data_len - pat_len);
        for i in (wrap_start..=(data_len - pat_len)).rev() {
            if self.data[i..i + pat_len] == *pattern {
                self.cursor = i as u64;
                return Some(i as u64);
            }
        }
        None
    }

    /// Add a bookmark at `offset` with `name` and return its unique id.
    pub fn bookmark(&mut self, offset: u64, name: &str) -> BookmarkId {
        let id = BookmarkId(self.next_bookmark_id);
        self.next_bookmark_id += 1;
        self.bookmarks.push(NavBookmark {
            id,
            offset,
            name: name.to_owned(),
        });
        id
    }

    /// Return all bookmarks, sorted by offset.
    #[must_use]
    pub fn bookmarks(&self) -> Vec<&NavBookmark> {
        let mut v: Vec<&NavBookmark> = self.bookmarks.iter().collect();
        v.sort_by_key(|b| b.offset);
        v
    }

    /// Remove a bookmark by id.  Returns `true` if it existed.
    pub fn remove_bookmark(&mut self, id: BookmarkId) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.id != id);
        self.bookmarks.len() < before
    }

    /// Replace the backing buffer.
    pub fn update_data(&mut self, data: Arc<Vec<u8>>) {
        self.data = data;
        if let Some(new_len) = self.data.len().checked_sub(1) {
            self.cursor = self.cursor.min(new_len as u64);
        } else {
            self.cursor = 0;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexExportFormat + exporter
// ─────────────────────────────────────────────────────────────────────────────

/// Output format for the hex exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HexExportFormat {
    /// C / C++ `uint8_t` array literal.
    CArray,
    /// Intel HEX (IHEX) record format.
    IntelHex,
    /// Motorola S-Record format.
    SRecord,
    /// Python `bytes` literal.
    PythonBytes,
    /// `xxd`-compatible hex dump.
    Xxd,
}

/// Export `data` in the requested format.
///
/// Returns a `String` containing the fully formatted output ready to be
/// written to a file or displayed in the UI.
#[must_use]
pub fn export(data: &[u8], format: HexExportFormat) -> String {
    match format {
        HexExportFormat::CArray => export_c_array(data),
        HexExportFormat::IntelHex => export_intel_hex(data),
        HexExportFormat::SRecord => export_s_record(data),
        HexExportFormat::PythonBytes => export_python_bytes(data),
        HexExportFormat::Xxd => export_xxd(data),
    }
}

// ── C array ──────────────────────────────────────────────────────────────────

fn export_c_array(data: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "/* {} bytes */\nuint8_t data[{}] = {{\n",
        data.len(),
        data.len()
    ));
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str("    ");
        for (j, &b) in chunk.iter().enumerate() {
            let comma = if i * 16 + j + 1 < data.len() { "," } else { "" };
            out.push_str(&format!("0x{b:02X}{comma}"));
            if j + 1 < chunk.len() {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out.push_str("};\n");
    out
}

// ── Intel HEX ────────────────────────────────────────────────────────────────

/// Compute the Intel HEX checksum byte.
fn ihex_checksum(bytes: &[u8]) -> u8 {
    let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
    ((!sum).wrapping_add(1) & 0xFF) as u8
}

fn export_intel_hex(data: &[u8]) -> String {
    const RECORD_LEN: usize = 16;
    let mut out = String::new();

    for (chunk_idx, chunk) in data.chunks(RECORD_LEN).enumerate() {
        let address = (chunk_idx * RECORD_LEN) as u16;
        let byte_count = chunk.len() as u8;
        let addr_hi = (address >> 8) as u8;
        let addr_lo = (address & 0xFF) as u8;

        let mut record_bytes: Vec<u8> = vec![byte_count, addr_hi, addr_lo, 0x00];
        record_bytes.extend_from_slice(chunk);
        let checksum = ihex_checksum(&record_bytes);
        record_bytes.push(checksum);

        out.push(':');
        for &b in &record_bytes {
            out.push_str(&format!("{b:02X}"));
        }
        out.push('\n');
    }

    // EOF record
    out.push_str(":00000001FF\n");
    out
}

// ── Motorola S-Record ─────────────────────────────────────────────────────────

/// Compute the Motorola S-Record checksum (one's complement of byte sum).
fn srec_checksum(bytes: &[u8]) -> u8 {
    let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
    (!sum & 0xFF) as u8
}

fn export_s_record(data: &[u8]) -> String {
    const RECORD_LEN: usize = 16;
    let mut out = String::new();

    // S0 header record
    let header_data = b"HDR";
    let byte_count = (header_data.len() + 2 + 1) as u8; // addr(2) + data + checksum(1)
    let cs_bytes: Vec<u8> = std::iter::once(byte_count)
        .chain([0x00u8, 0x00])
        .chain(header_data.iter().copied())
        .collect();
    let cs = srec_checksum(&cs_bytes);
    out.push_str(&format!("S0{byte_count:02X}0000"));
    for &b in header_data {
        out.push_str(&format!("{b:02X}"));
    }
    out.push_str(&format!("{cs:02X}\n"));

    // S1 data records (16-bit address)
    for (chunk_idx, chunk) in data.chunks(RECORD_LEN).enumerate() {
        let address = (chunk_idx * RECORD_LEN) as u16;
        let byte_count = (chunk.len() + 2 + 1) as u8; // addr(2) + data + checksum(1)
        let addr_hi = (address >> 8) as u8;
        let addr_lo = (address & 0xFF) as u8;

        let mut cs_bytes: Vec<u8> = vec![byte_count, addr_hi, addr_lo];
        cs_bytes.extend_from_slice(chunk);
        let cs = srec_checksum(&cs_bytes);
        cs_bytes.push(cs);

        out.push_str(&format!("S1{byte_count:02X}"));
        for &b in &cs_bytes[1..] {
            out.push_str(&format!("{b:02X}"));
        }
        out.push('\n');
    }

    // S9 end record
    out.push_str("S9030000FC\n");
    out
}

// ── Python bytes ──────────────────────────────────────────────────────────────

fn export_python_bytes(data: &[u8]) -> String {
    let mut out = String::from("data = b\"");
    for &b in data {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push_str("\"\n");
    out
}

// ── xxd ──────────────────────────────────────────────────────────────────────

fn export_xxd(data: &[u8]) -> String {
    const COLS: usize = 16;
    let mut out = String::new();

    for (row, chunk) in data.chunks(COLS).enumerate() {
        let offset = row * COLS;
        // Offset column
        out.push_str(&format!("{offset:08x}: "));
        // Hex pairs in groups of 2
        for (i, &b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02x}"));
            if i % 2 == 1 {
                out.push(' ');
            }
        }
        // Pad incomplete last row
        let pad_bytes = COLS - chunk.len();
        for i in 0..pad_bytes {
            out.push_str("  ");
            if (chunk.len() + i) % 2 == 1 {
                out.push(' ');
            }
        }
        // ASCII column
        out.push(' ');
        for &b in chunk {
            out.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for HexViewModel, HexNavigator, HexExportFormat
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_new_view {
    use super::*;

    fn arc_data(bytes: Vec<u8>) -> Arc<Vec<u8>> {
        Arc::new(bytes)
    }

    // ── HexViewModel ──────────────────────────────────────────────────────────

    #[test]
    fn test_hex_view_model_total_rows() {
        let vm = HexViewModel::new(arc_data(vec![0u8; 32]));
        assert_eq!(vm.total_rows(), 2); // 32 / 16 == 2
    }

    #[test]
    fn test_hex_view_model_total_rows_partial() {
        let vm = HexViewModel::new(arc_data(vec![0u8; 17]));
        assert_eq!(vm.total_rows(), 2); // ceil(17/16)
    }

    #[test]
    fn test_hex_view_model_visible_range_full() {
        let vm = HexViewModel::new(arc_data((0u8..=31).collect()));
        let rows = vm.visible_range(0, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].offset, 0);
        assert_eq!(rows[1].offset, 16);
    }

    #[test]
    fn test_hex_view_model_visible_range_beyond_end() {
        let vm = HexViewModel::new(arc_data(vec![1u8; 10]));
        let rows = vm.visible_range(0, 100); // request far more rows than exist
        assert_eq!(rows.len(), 1); // only one row for 10 bytes with bpr=16
    }

    #[test]
    fn test_hex_view_model_visible_range_offset() {
        let vm = HexViewModel::new(arc_data((0u8..=31).collect()));
        let rows = vm.visible_range(1, 1); // row 1 starts at byte 16
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].offset, 16);
        assert_eq!(rows[0].bytes[0], 16);
    }

    #[test]
    fn test_hex_row_hex_str() {
        let vm = HexViewModel::new(arc_data(vec![0xDEu8, 0xAD, 0xBE, 0xEF]));
        let rows = vm.visible_range(0, 1);
        assert_eq!(rows[0].hex_str, "DE AD BE EF");
    }

    #[test]
    fn test_hex_row_ascii_nonprintable() {
        let vm = HexViewModel::new(arc_data(vec![0x00u8, 0x41, 0xFF]));
        let rows = vm.visible_range(0, 1);
        assert_eq!(rows[0].ascii, ".A.");
    }

    #[test]
    fn test_hex_view_model_is_empty() {
        let vm = HexViewModel::new(arc_data(vec![]));
        assert!(vm.is_empty());
        let rows = vm.visible_range(0, 10);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_hex_view_model_custom_bpr() {
        let mut vm = HexViewModel::new(arc_data(vec![0u8; 8]));
        vm.bytes_per_row = 4;
        assert_eq!(vm.total_rows(), 2);
        let rows = vm.visible_range(0, 2);
        assert_eq!(rows[0].bytes.len(), 4);
        assert_eq!(rows[1].bytes.len(), 4);
    }

    // ── HexNavigator ──────────────────────────────────────────────────────────

    #[test]
    fn test_navigator_goto_offset() {
        let mut nav = HexNavigator::new(arc_data(vec![0u8; 64]));
        let state = nav.goto_offset(32);
        assert_eq!(state.offset, 32);
        assert_eq!(state.row, 2);
        assert_eq!(state.col, 0);
    }

    #[test]
    fn test_navigator_goto_offset_clamped() {
        let mut nav = HexNavigator::new(arc_data(vec![0u8; 8]));
        let state = nav.goto_offset(1000);
        assert_eq!(state.offset, 7); // clamped to len-1
    }

    #[test]
    fn test_navigator_find_next() {
        let data = b"Hello, world! Hello.".to_vec();
        let mut nav = HexNavigator::new(arc_data(data));
        nav.cursor = 0;
        let found = nav.find_next(b"Hello");
        assert_eq!(found, Some(0));
        let found2 = nav.find_next(b"Hello");
        assert_eq!(found2, Some(14));
    }

    #[test]
    fn test_navigator_find_next_not_found() {
        let mut nav = HexNavigator::new(arc_data(b"AAAA".to_vec()));
        let found = nav.find_next(b"ZZ");
        assert_eq!(found, None);
    }

    #[test]
    fn test_navigator_find_prev() {
        let data = b"Hello, world! Hello.".to_vec();
        let mut nav = HexNavigator::new(arc_data(data));
        nav.cursor = 19; // at the end
        let found = nav.find_prev(b"Hello");
        assert!(found.is_some());
    }

    #[test]
    fn test_navigator_bookmark_add_and_list() {
        let mut nav = HexNavigator::new(arc_data(vec![0u8; 64]));
        let id1 = nav.bookmark(10, "start");
        let id2 = nav.bookmark(40, "middle");
        let bmarks = nav.bookmarks();
        assert_eq!(bmarks.len(), 2);
        assert_eq!(bmarks[0].offset, 10);
        assert_eq!(bmarks[0].id, id1);
        assert_eq!(bmarks[1].id, id2);
    }

    #[test]
    fn test_navigator_bookmark_remove() {
        let mut nav = HexNavigator::new(arc_data(vec![0u8; 32]));
        let id = nav.bookmark(5, "test");
        let removed = nav.remove_bookmark(id);
        assert!(removed);
        assert!(nav.bookmarks().is_empty());
    }

    #[test]
    fn test_navigator_bookmark_sorted() {
        let mut nav = HexNavigator::new(arc_data(vec![0u8; 64]));
        nav.bookmark(50, "late");
        nav.bookmark(10, "early");
        nav.bookmark(30, "mid");
        let bmarks = nav.bookmarks();
        let offsets: Vec<u64> = bmarks.iter().map(|b| b.offset).collect();
        assert_eq!(offsets, vec![10, 30, 50]);
    }

    // ── HexExportFormat ───────────────────────────────────────────────────────

    #[test]
    fn test_export_c_array_contains_header() {
        let s = export(&[0xDEu8, 0xAD], HexExportFormat::CArray);
        assert!(s.contains("uint8_t data[2]"));
        assert!(s.contains("0xDE"));
        assert!(s.contains("0xAD"));
    }

    #[test]
    fn test_export_c_array_empty() {
        let s = export(&[], HexExportFormat::CArray);
        assert!(s.contains("data[0]"));
    }

    #[test]
    fn test_export_intel_hex_has_eof() {
        let s = export(b"Hello", HexExportFormat::IntelHex);
        assert!(s.contains(":00000001FF"));
    }

    #[test]
    fn test_export_intel_hex_record_starts_with_colon() {
        let s = export(b"AB", HexExportFormat::IntelHex);
        for line in s.lines() {
            assert!(
                line.starts_with(':'),
                "Expected ':' at start of line: {line}"
            );
        }
    }

    #[test]
    fn test_export_s_record_has_end() {
        let s = export(b"Hi", HexExportFormat::SRecord);
        assert!(s.contains("S9"));
    }

    #[test]
    fn test_export_s_record_starts_with_s0() {
        let s = export(b"Hi", HexExportFormat::SRecord);
        assert!(s.starts_with("S0"));
    }

    #[test]
    fn test_export_python_bytes_format() {
        let s = export(b"AB\x00", HexExportFormat::PythonBytes);
        assert!(s.starts_with("data = b\""));
        assert!(s.contains("AB"));
        assert!(s.contains("\\x00"));
    }

    #[test]
    fn test_export_xxd_offset_column() {
        let data: Vec<u8> = (0u8..32).collect();
        let s = export(&data, HexExportFormat::Xxd);
        assert!(s.starts_with("00000000:"));
        assert!(s.contains("00000010:"));
    }

    #[test]
    fn test_export_xxd_ascii_column() {
        let s = export(b"Hello", HexExportFormat::Xxd);
        assert!(s.contains("Hello"));
    }

    #[test]
    fn test_export_python_bytes_escapes_backslash() {
        let s = export(b"a\\b", HexExportFormat::PythonBytes);
        assert!(s.contains("\\\\"));
    }

    #[test]
    fn test_export_python_bytes_escapes_quote() {
        let s = export(b"a\"b", HexExportFormat::PythonBytes);
        assert!(s.contains("\\\""));
    }
}
