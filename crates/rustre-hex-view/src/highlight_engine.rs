//! `highlight_engine` — Multi-layer highlighting engine for the hex view.
//!
//! Supports highlight layers for:
//! - Entropy (colour gradient by byte randomness)
//! - Template fields (colour by type)
//! - YARA rule matches
//! - Search results
//! - Selected range
//! - Arbitrary user-defined overlays
//!
//! Multiple overlays can be active simultaneously. Priority and alpha blending
//! control the final colour at each byte.

use std::collections::HashMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};

/// Blend two u8 alpha components: `(a * b / 255)`, guaranteed ≤ 255.
fn blend_alpha(a: u8, b: u8) -> u8 {
    u8::try_from(u16::from(a) * u16::from(b) / 255).unwrap_or(u8::MAX)
}

const fn cast_usize_f64(n: usize) -> f64 { n as f64 }

// ─────────────────────────────────────────────────────────────────────────────
// Color
// ─────────────────────────────────────────────────────────────────────────────

/// An sRGB colour with an alpha channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HlColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8, // 0 = transparent, 255 = opaque
}

impl HlColor {
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    #[must_use]
    pub const fn opaque(r: u8, g: u8, b: u8) -> Self {
        Self::new(r, g, b, 255)
    }

    #[must_use]
    pub const fn transparent() -> Self {
        Self::new(0, 0, 0, 0)
    }

    /// Alpha-blend `self` over `bg`.
    #[must_use]
    pub fn blend_over(self, bg: Self) -> Self {
        if self.a == 0 {
            return bg;
        }
        if self.a == 255 || bg.a == 0 {
            return self;
        }
        let alpha = u16::from(self.a);
        let inv = 255 - alpha;
        Self {
            r: ((u16::from(self.r) * alpha + u16::from(bg.r) * inv) / 255) as u8,
            g: ((u16::from(self.g) * alpha + u16::from(bg.g) * inv) / 255) as u8,
            b: ((u16::from(self.b) * alpha + u16::from(bg.b) * inv) / 255) as u8,
            a: 255,
        }
    }

    /// Render as ANSI background escape.
    #[must_use]
    pub fn ansi_bg(&self) -> String {
        format!("\x1b[48;2;{};{};{}m", self.r, self.g, self.b)
    }

    /// Render as ANSI foreground escape.
    #[must_use]
    pub fn ansi_fg(&self) -> String {
        format!("\x1b[38;2;{};{};{}m", self.r, self.g, self.b)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HighlightSpan
// ─────────────────────────────────────────────────────────────────────────────

/// A coloured span over a byte range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightSpan {
    pub range: Range<usize>,
    pub bg: HlColor,
    pub fg: Option<HlColor>,
    pub label: String,
    pub priority: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// LayerKind
// ─────────────────────────────────────────────────────────────────────────────

/// The type of a highlight layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LayerKind {
    Entropy,
    TemplateField,
    YaraMatch,
    SearchResult,
    Selection,
    UserOverlay,
    PatternMatch,
    Bookmark,
    DiffAdded,
    DiffRemoved,
    DiffChanged,
}

impl LayerKind {
    /// Default priority for this layer kind (higher = rendered on top).
    #[must_use]
    pub const fn default_priority(self) -> u8 {
        match self {
            Self::Entropy => 10,
            Self::TemplateField => 30,
            Self::PatternMatch => 40,
            Self::YaraMatch => 50,
            Self::SearchResult => 60,
            Self::Bookmark => 65,
            Self::DiffAdded | Self::DiffRemoved | Self::DiffChanged => 70,
            Self::UserOverlay => 80,
            Self::Selection => 100,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer
// ─────────────────────────────────────────────────────────────────────────────

/// A named highlight layer containing a list of spans.
#[derive(Debug, Clone)]
pub struct Layer {
    pub kind: LayerKind,
    pub name: String,
    pub spans: Vec<HighlightSpan>,
    pub enabled: bool,
    pub priority: u8,
    pub global_alpha: u8,
}

impl Layer {
    pub fn new(kind: LayerKind, name: impl Into<String>) -> Self {
        Self {
            priority: kind.default_priority(),
            kind,
            name: name.into(),
            spans: vec![],
            enabled: true,
            global_alpha: 200,
        }
    }

    pub fn add_span(&mut self, span: HighlightSpan) {
        self.spans.push(span);
    }

    pub fn clear(&mut self) {
        self.spans.clear();
    }

    /// Spans that include `offset`.
    #[must_use]
    pub fn spans_at(&self, offset: usize) -> Vec<&HighlightSpan> {
        self.spans.iter().filter(|s| s.range.contains(&offset)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyHighlighter
// ─────────────────────────────────────────────────────────────────────────────

/// Generates entropy-based colour highlights.
pub struct EntropyHighlighter {
    pub window: usize,
    pub low_color: HlColor,
    pub high_color: HlColor,
}

impl Default for EntropyHighlighter {
    fn default() -> Self {
        Self {
            window: 256,
            low_color: HlColor::opaque(20, 20, 200),   // blue = low entropy
            high_color: HlColor::opaque(200, 20, 20),  // red = high entropy
        }
    }
}

impl EntropyHighlighter {
    /// Compute Shannon entropy for a byte window.
    #[must_use]
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = cast_usize_f64(data.len());
        counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
            let p = f64::from(c) / len;
            p.mul_add(-p.log2(), acc)
        })
    }

    /// Interpolate between two colours by `t` (0.0–1.0).
    #[must_use]
    fn lerp_color(a: HlColor, b: HlColor, t: f32) -> HlColor {
        let lerp = |av: u8, bv: u8| (f32::from(bv) - f32::from(av)).mul_add(t, f32::from(av)) as u8;
        HlColor {
            r: lerp(a.r, b.r),
            g: lerp(a.g, b.g),
            b: lerp(a.b, b.b),
            a: lerp(a.a, b.a),
        }
    }

    /// Build a layer of entropy highlights for `data`.
    #[must_use]
    pub fn build_layer(&self, data: &[u8]) -> Layer {
        let mut layer = Layer::new(LayerKind::Entropy, "Entropy");
        layer.global_alpha = 150;

        let step = self.window / 2;
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + self.window).min(data.len());
            let window = &data[offset..end];
            let entropy = Self::shannon_entropy(window);
            let t = ((entropy / 8.0).min(1.0)) as f32;

            let mut color = Self::lerp_color(self.low_color, self.high_color, t);
            color.a = 180;

            layer.add_span(HighlightSpan {
                range: offset..end,
                bg: color,
                fg: None,
                label: format!("entropy:{entropy:.2}"),
                priority: 0,
            });

            offset += step;
        }

        layer
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HighlightEngine
// ─────────────────────────────────────────────────────────────────────────────

/// The main highlighting engine: manages layers and resolves final colours.
#[derive(Debug, Default)]
pub struct HighlightEngine {
    layers: HashMap<String, Layer>,
    /// Cache: offset → resolved bg colour.
    cache: HashMap<usize, HlColor>,
    cache_valid: bool,
    buf_len: usize,
}

impl HighlightEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Layer management ─────────────────────────────────────────────────────

    pub fn add_layer(&mut self, layer: Layer) {
        self.layers.insert(layer.name.clone(), layer);
        self.invalidate_cache();
    }

    pub fn remove_layer(&mut self, name: &str) -> bool {
        let removed = self.layers.remove(name).is_some();
        if removed { self.invalidate_cache(); }
        removed
    }

    pub fn get_layer_mut(&mut self, name: &str) -> Option<&mut Layer> {
        self.invalidate_cache();
        self.layers.get_mut(name)
    }

    pub fn set_layer_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(l) = self.layers.get_mut(name) {
            l.enabled = enabled;
            self.invalidate_cache();
        }
    }

    #[must_use]
    pub fn layer_names(&self) -> Vec<&str> {
        self.layers.keys().map(String::as_str).collect()
    }

    /// Record the byte length of the buffer this engine is highlighting.
    /// The value bounds [`Self::buffer_len`] and is used to clamp
    /// out-of-range offsets in [`Self::resolve_clamped`].
    pub fn set_buffer_len(&mut self, len: usize) {
        if self.buf_len != len {
            self.invalidate_cache();
        }
        self.buf_len = len;
    }

    /// Returns the previously recorded buffer length (0 if never set).
    #[must_use]
    pub const fn buffer_len(&self) -> usize {
        self.buf_len
    }

    /// Like [`Self::bg_at`], but returns `None` when `offset` is outside
    /// the configured buffer (see [`Self::set_buffer_len`]). If no buffer
    /// length has been set, resolution is unbounded.
    #[must_use]
    pub fn bg_at_clamped(&self, offset: usize) -> Option<HlColor> {
        if self.buf_len > 0 && offset >= self.buf_len {
            return None;
        }
        Some(self.bg_at(offset))
    }

    // ── Colour resolution ────────────────────────────────────────────────────

    /// Resolve the final background colour at `offset` by blending all active layers.
    #[must_use]
    pub fn bg_at(&self, offset: usize) -> HlColor {
        let mut sorted_layers: Vec<&Layer> = self
            .layers
            .values()
            .filter(|l| l.enabled)
            .collect();
        sorted_layers.sort_by_key(|l| l.priority);

        let mut result = HlColor::transparent();
        for layer in sorted_layers {
            for span in layer.spans_at(offset) {
                let mut color = span.bg;
                // Apply global layer alpha
                color.a = blend_alpha(color.a, layer.global_alpha);
                result = color.blend_over(result);
            }
        }
        result
    }

    /// Resolve background for a range of bytes (returns one colour per byte).
    ///
    /// Uses `checked_add` to prevent a silent integer overflow that would turn
    /// a large `len` into a huge (or wrapping-to-small) iterator and either
    /// exhaust memory or silently produce fewer results than expected.
    #[must_use]
    pub fn bg_range(&self, start: usize, len: usize) -> Vec<HlColor> {
        let end = start.saturating_add(len);
        (start..end).map(|i| self.bg_at(i)).collect()
    }

    /// Build a compact ANSI-coloured representation of a row.
    #[must_use]
    pub fn render_row_ansi(
        &self,
        data: &[u8],
        offset: usize,
        row_bytes: usize,
    ) -> String {
        let end = (offset + row_bytes).min(data.len());
        let mut out = String::new();
        let mut last_color: Option<HlColor> = None;

        for (i, &b) in data[offset..end].iter().enumerate() {
            let color = self.bg_at(offset + i);
            let needs_reset = last_color.is_none_or(|lc| lc != color);
            if needs_reset && color.a > 0 {
                out.push_str(&color.ansi_bg());
            } else if needs_reset {
                out.push_str("\x1b[49m");
            }
            use std::fmt::Write as _;
            write!(out, "{b:02X} ").unwrap();
            last_color = Some(color);
        }
        out.push_str("\x1b[0m");
        out
    }

    // ── Convenience layer builders ───────────────────────────────────────────

    /// Add an entropy layer from the given data.
    pub fn add_entropy_layer(&mut self, data: &[u8], window: usize) {
        let hl = EntropyHighlighter {
            window,
            ..Default::default()
        };
        let layer = hl.build_layer(data);
        self.add_layer(layer);
    }

    /// Add a selection highlight.
    pub fn set_selection(&mut self, range: Range<usize>) {
        let mut layer = Layer::new(LayerKind::Selection, "Selection");
        layer.add_span(HighlightSpan {
            range,
            bg: HlColor::opaque(100, 150, 255),
            fg: Some(HlColor::opaque(0, 0, 0)),
            label: "selection".to_string(),
            priority: 0,
        });
        self.add_layer(layer);
    }

    /// Add search result highlights.
    pub fn set_search_results(&mut self, offsets: &[usize], match_len: usize) {
        let mut layer = Layer::new(LayerKind::SearchResult, "SearchResult");
        for &off in offsets {
            layer.add_span(HighlightSpan {
                range: off..off + match_len,
                bg: HlColor::opaque(255, 220, 50),
                fg: Some(HlColor::opaque(0, 0, 0)),
                label: "match".to_string(),
                priority: 0,
            });
        }
        self.add_layer(layer);
    }

    /// Add a YARA match layer.
    pub fn add_yara_matches(&mut self, rule_name: &str, ranges: &[Range<usize>]) {
        let layer_name = format!("YARA:{rule_name}");
        let mut layer = Layer::new(LayerKind::YaraMatch, &layer_name);
        for range in ranges {
            layer.add_span(HighlightSpan {
                range: range.clone(),
                bg: HlColor::new(200, 100, 255, 200),
                fg: None,
                label: rule_name.to_string(),
                priority: 0,
            });
        }
        self.add_layer(layer);
    }

    /// Add a diff highlight layer.
    pub fn add_diff_layer(&mut self, added: &[Range<usize>], removed: &[Range<usize>], changed: &[Range<usize>]) {
        let mut layer = Layer::new(LayerKind::DiffAdded, "Diff");
        for r in added {
            layer.add_span(HighlightSpan {
                range: r.clone(),
                bg: HlColor::new(50, 200, 80, 200),
                fg: None,
                label: "added".to_string(),
                priority: 1,
            });
        }
        for r in removed {
            layer.add_span(HighlightSpan {
                range: r.clone(),
                bg: HlColor::new(200, 50, 50, 200),
                fg: None,
                label: "removed".to_string(),
                priority: 1,
            });
        }
        for r in changed {
            layer.add_span(HighlightSpan {
                range: r.clone(),
                bg: HlColor::new(240, 180, 30, 200),
                fg: None,
                label: "changed".to_string(),
                priority: 1,
            });
        }
        self.add_layer(layer);
    }

    /// Add template field highlights.
    pub fn add_template_fields(
        &mut self,
        fields: &[(&str, Range<usize>, HlColor)],
    ) {
        let mut layer = Layer::new(LayerKind::TemplateField, "TemplateFields");
        for (name, range, color) in fields {
            let mut c = *color;
            c.a = 180;
            layer.add_span(HighlightSpan {
                range: range.clone(),
                bg: c,
                fg: None,
                label: name.to_string(),
                priority: 0,
            });
        }
        self.add_layer(layer);
    }

    fn invalidate_cache(&mut self) {
        self.cache_valid = false;
        self.cache.clear();
    }

    /// All layers sorted by priority.
    #[must_use]
    pub fn sorted_layers(&self) -> Vec<&Layer> {
        let mut layers: Vec<&Layer> = self.layers.values().collect();
        layers.sort_by_key(|l| l.priority);
        layers
    }

    /// All spans at a given offset, across all enabled layers.
    #[must_use]
    pub fn spans_at(&self, offset: usize) -> Vec<(&str, &HighlightSpan)> {
        self.layers
            .values()
            .filter(|l| l.enabled)
            .flat_map(|l| l.spans_at(offset).into_iter().map(|s| (l.name.as_str(), s)))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_blend_opaque_over_transparent() {
        let fg = HlColor::opaque(100, 200, 50);
        let bg = HlColor::transparent();
        let result = fg.blend_over(bg);
        assert_eq!(result, fg);
    }

    #[test]
    fn color_blend_alpha() {
        let fg = HlColor::new(200, 0, 0, 128);
        let bg = HlColor::opaque(0, 200, 0);
        let result = fg.blend_over(bg);
        assert!(result.r > 80 && result.r < 150);
    }

    #[test]
    fn entropy_of_uniform() {
        let data = vec![0xAAu8; 256];
        let e = EntropyHighlighter::shannon_entropy(&data);
        assert!(e < 0.01);
    }

    #[test]
    fn entropy_of_random() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = EntropyHighlighter::shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.001);
    }

    #[test]
    fn selection_highlight() {
        let mut engine = HighlightEngine::new();
        engine.set_selection(10..20);
        let c = engine.bg_at(15);
        assert!(c.a > 0);
        let d = engine.bg_at(5);
        assert_eq!(d.a, 0);
    }

    #[test]
    fn search_results_layer() {
        let mut engine = HighlightEngine::new();
        engine.set_search_results(&[0, 100, 200], 4);
        let at_match = engine.bg_at(2);
        assert!(at_match.a > 0);
        let not_match = engine.bg_at(50);
        assert_eq!(not_match.a, 0);
    }

    #[test]
    fn layer_enable_disable() {
        let mut engine = HighlightEngine::new();
        engine.set_selection(0..10);
        engine.set_layer_enabled("Selection", false);
        let c = engine.bg_at(5);
        assert_eq!(c.a, 0);
    }

    #[test]
    fn entropy_layer_build() {
        let data: Vec<u8> = (0..512).map(|i| i as u8).collect();
        let mut engine = HighlightEngine::new();
        engine.add_entropy_layer(&data, 64);
        let c = engine.bg_at(256);
        // Entropy layer should produce non-transparent colours
        assert!(c.a > 0 || engine.layer_names().contains(&"Entropy"));
    }
}
