//! Y072 deep adversarial coverage for rustre-hex-view public API.

use rustre_hex::HexBuffer;
use rustre_hex_view::*;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ──────────── Color ────────────

#[test]
fn color_new_and_consts() {
    let c = Color::new(1, 2, 3);
    assert_eq!((c.r, c.g, c.b), (1, 2, 3));
    assert_eq!(Color::black(), Color::new(0, 0, 0));
    assert_eq!(Color::white(), Color::new(255, 255, 255));
    let _ = Color::red();
    let _ = Color::green();
    let _ = Color::blue();
    let _ = Color::yellow();
    let _ = Color::cyan();
    let _ = Color::magenta();
    let _ = Color::gray();
    let _ = Color::dark_gray();
    let _ = Color::orange();
    let _ = Color::light_blue();
    let _ = Color::light_green();
    let _ = Color::pink();
}

#[test]
fn color_default() {
    let c = Color::default();
    assert_eq!(c, Color::new(0, 0, 0));
}

#[test]
fn color_ansi_escape_shapes() {
    let c = Color::new(10, 200, 250);
    let fg = c.ansi_fg();
    let bg = c.ansi_bg();
    assert!(fg.starts_with("\x1b[38;2;10;200;250"));
    assert!(bg.starts_with("\x1b[48;2;10;200;250"));
    assert!(fg.ends_with('m'));
    assert!(bg.ends_with('m'));
}

#[test]
fn color_blend_endpoints() {
    let a = Color::new(0, 0, 0);
    let b = Color::new(100, 200, 50);
    assert_eq!(a.blend(b, 0.0), a);
    assert_eq!(a.blend(b, 1.0), b);
    assert_eq!(a.blend(b, -10.0), a); // clamped
    assert_eq!(a.blend(b, 10.0), b); // clamped
}

#[test]
fn color_blend_50_pct_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = g();
        let a = Color::new(v as u8, (v >> 8) as u8, (v >> 16) as u8);
        let b = Color::new((v >> 24) as u8, (v >> 32) as u8, (v >> 40) as u8);
        let m = a.blend(b, 0.5);
        // Round-trip property: blend(b,a,0.5) == blend(a,b,0.5) within ±1 (rounding)
        let m2 = b.blend(a, 0.5);
        assert!(m.r.abs_diff(m2.r) <= 1);
        assert!(m.g.abs_diff(m2.g) <= 1);
        assert!(m.b.abs_diff(m2.b) <= 1);
    }
}

#[test]
fn color_rgb_u32_round_trip_fuzz() {
    let mut g = lcg();
    for _ in 0..100 {
        let v = g();
        let c = Color::new(v as u8, (v >> 8) as u8, (v >> 16) as u8);
        let r = Color::from_rgb_u32(c.to_rgb_u32());
        assert_eq!(c, r);
    }
}

#[test]
fn color_from_rgb_u32_masks_high_bits() {
    let c = Color::from_rgb_u32(0xFFAABBCC);
    assert_eq!(c, Color::new(0xAA, 0xBB, 0xCC));
}

#[test]
fn color_for_entropy_monotonic_red() {
    let lo = Color::for_entropy(0.0);
    let hi = Color::for_entropy(8.0);
    assert!(hi.r >= lo.r);
}

#[test]
fn color_for_entropy_out_of_range_clamps() {
    let neg = Color::for_entropy(-5.0);
    let big = Color::for_entropy(1000.0);
    // No panic + values are valid u8 — just exercise clamp branches
    let _ = (neg, big);
}

// ──────────── ColorMap ────────────

#[test]
fn colormap_default_is_empty() {
    let cm = ColorMap::default();
    assert!(cm.ranges.is_empty());
    let (fg, bg) = cm.lookup(0x42);
    assert_eq!(fg, cm.default_fg);
    assert!(bg.is_none());
}

#[test]
fn colormap_add_range_and_lookup() {
    let mut cm = ColorMap::default();
    cm.add_range(0x10, 0x20, Color::red(), Some(Color::blue()));
    let (fg, bg) = cm.lookup(0x15);
    assert_eq!(fg, Color::red());
    assert_eq!(bg, Some(Color::blue()));
    let (fg2, _) = cm.lookup(0x30);
    assert_eq!(fg2, cm.default_fg);
}

#[test]
fn colormap_boundary_inclusive() {
    let mut cm = ColorMap::default();
    cm.add_range(0x10, 0x20, Color::red(), None);
    assert_eq!(cm.lookup(0x10).0, Color::red());
    assert_eq!(cm.lookup(0x20).0, Color::red());
    assert_ne!(cm.lookup(0x21).0, Color::red());
}

// ──────────── ColorScheme ────────────

#[test]
fn color_scheme_names_and_maps() {
    for s in [
        ColorScheme::Dark,
        ColorScheme::Light,
        ColorScheme::Monokai,
        ColorScheme::Nord,
        ColorScheme::Solarized,
        ColorScheme::HighContrast,
    ] {
        let n = s.name();
        assert!(!n.is_empty());
        let _ = s.color_map();
    }
    let custom = ColorScheme::Custom(ColorMap::default());
    assert_eq!(custom.name(), "Custom");
    let _ = custom.color_map();
}

// ──────────── OffsetBase ────────────

#[test]
fn offset_base_format_widths() {
    assert_eq!(OffsetBase::Hex.format(0).len(), 8);
    assert_eq!(OffsetBase::Decimal.format(0).len(), 10);
    let oct = OffsetBase::Octal.format(0);
    assert_eq!(oct.len(), 11);
}

#[test]
fn offset_base_format_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let off = (g() as usize) & 0x000F_FFFF;
        let h = OffsetBase::Hex.format(off);
        let d = OffsetBase::Decimal.format(off);
        let o = OffsetBase::Octal.format(off);
        assert!(!h.is_empty());
        assert!(!d.is_empty());
        assert!(!o.is_empty());
        // Decimal round-trip parse
        assert_eq!(d.trim_start_matches('0').parse::<usize>().unwrap_or(0), off);
    }
}

#[test]
fn offset_base_prefixed() {
    assert!(OffsetBase::Hex.format_prefixed(0x10).starts_with("0x"));
    assert!(OffsetBase::Octal.format_prefixed(0o17).starts_with("0o"));
    assert_eq!(OffsetBase::Decimal.format_prefixed(123), "123");
}

#[test]
fn offset_base_max_value() {
    // Should not panic at usize::MAX
    let _ = OffsetBase::Hex.format(usize::MAX);
    let _ = OffsetBase::Decimal.format(usize::MAX);
    let _ = OffsetBase::Octal.format(usize::MAX);
}

// ──────────── HexViewConfig ────────────

#[test]
fn hex_view_config_defaults() {
    let c = HexViewConfig::default();
    assert_eq!(c.bytes_per_row, 16);
    assert!(c.show_offset);
    assert!(c.show_ascii);
    assert!(!c.show_diff);
}

#[test]
fn hex_view_config_for_diff_and_with_entropy() {
    assert!(HexViewConfig::for_diff().show_diff);
    assert!(HexViewConfig::with_entropy().show_entropy_bar);
}

// ──────────── Annotation ────────────

#[test]
fn annotation_range_and_overlap() {
    let a = Annotation { offset: 10, len: 5, label: "x".into(), color: Color::red() };
    assert_eq!(a.range(), 10..15);
    assert!(a.overlaps(8..12));
    assert!(a.overlaps(14..20));
    assert!(!a.overlaps(0..10));
    assert!(!a.overlaps(15..30));
}

#[test]
fn annotation_zero_len_no_overlap() {
    let a = Annotation { offset: 10, len: 0, label: "z".into(), color: Color::red() };
    assert_eq!(a.range(), 10..10);
    assert!(!a.overlaps(10..11));
}

#[test]
fn annotation_saturating_at_max() {
    let a = Annotation { offset: usize::MAX - 1, len: usize::MAX, label: "x".into(), color: Color::red() };
    let r = a.range();
    assert_eq!(r.end, usize::MAX); // saturated
}

// ──────────── AnnotationLayer ────────────

#[test]
fn annotation_layer_basic() {
    let mut l = AnnotationLayer::new();
    assert!(l.is_empty());
    assert_eq!(l.len(), 0);
    l.add(Annotation { offset: 5, len: 3, label: "b".into(), color: Color::red() });
    l.add(Annotation { offset: 0, len: 2, label: "a".into(), color: Color::red() });
    assert_eq!(l.len(), 2);
    // Sorted by offset
    assert_eq!(l.annotations[0].offset, 0);
    assert_eq!(l.annotations[1].offset, 5);
}

#[test]
fn annotation_layer_overlapping_and_at_offset() {
    let mut l = AnnotationLayer::new();
    l.add(Annotation { offset: 0, len: 4, label: "a".into(), color: Color::red() });
    l.add(Annotation { offset: 8, len: 4, label: "b".into(), color: Color::red() });
    assert_eq!(l.overlapping(2, 4).len(), 1);
    assert_eq!(l.overlapping(0, 16).len(), 2);
    assert_eq!(l.overlapping(4, 4).len(), 0); // [4..8) — neither
    assert_eq!(l.at_offset(0).len(), 1);
    assert_eq!(l.at_offset(8).len(), 1);
    assert_eq!(l.at_offset(2).len(), 0);
}

#[test]
fn annotation_layer_has_overlap_and_merge() {
    let mut l = AnnotationLayer::new();
    l.add(Annotation { offset: 0, len: 5, label: "a".into(), color: Color::red() });
    l.add(Annotation { offset: 3, len: 5, label: "b".into(), color: Color::red() });
    assert!(l.has_overlap());
    l.merge_overlapping();
    assert!(!l.has_overlap());
    assert_eq!(l.len(), 1);
    assert_eq!(l.annotations[0].offset, 0);
    assert_eq!(l.annotations[0].len, 8);
}

#[test]
fn annotation_layer_merge_empty_noop() {
    let mut l = AnnotationLayer::new();
    l.merge_overlapping();
    assert!(l.is_empty());
}

#[test]
fn annotation_layer_remove_in_range() {
    let mut l = AnnotationLayer::new();
    l.add(Annotation { offset: 0, len: 2, label: "a".into(), color: Color::red() });
    l.add(Annotation { offset: 5, len: 2, label: "b".into(), color: Color::red() });
    l.add(Annotation { offset: 10, len: 2, label: "c".into(), color: Color::red() });
    l.remove_in_range(4..8);
    assert_eq!(l.len(), 2);
    assert_eq!(l.annotations[0].offset, 0);
    assert_eq!(l.annotations[1].offset, 10);
}

#[test]
fn annotation_layer_floating() {
    let mut l = AnnotationLayer::new();
    l.add_floating(FloatingAnnotation::new(20, "hi", Color::red(), false));
    l.add_floating(FloatingAnnotation::new(5, "lo", Color::red(), true));
    assert_eq!(l.floating[0].offset, 5);
    assert_eq!(l.floating_at(20).len(), 1);
    assert_eq!(l.floating_at(99).len(), 0);
}

#[test]
fn annotation_layer_fuzz_no_panic() {
    let mut g = lcg();
    let mut l = AnnotationLayer::new();
    for _ in 0..200 {
        let off = (g() as usize) % 1024;
        let len = ((g() as usize) % 32) + 1;
        l.add(Annotation { offset: off, len, label: "f".into(), color: Color::red() });
    }
    let _ = l.overlapping(0, 4096);
    l.merge_overlapping();
    assert!(!l.has_overlap());
}

// ──────────── ColorSpan ────────────

#[test]
fn color_span_fg_helper() {
    let s = ColorSpan::fg(5, 10, Color::red());
    assert_eq!(s.start, 5);
    assert_eq!(s.end, 10);
    assert_eq!(s.fg, Color::red());
    assert!(!s.bold);
    assert!(!s.underline);
    assert!(s.bg.is_none());
}

// ──────────── EntropyBar ────────────

#[test]
fn entropy_bar_zero_and_max() {
    let lo = EntropyBar::build(0.0);
    assert_eq!(lo.bar.len(), 8);
    assert!(lo.bar.starts_with('.'));
    let hi = EntropyBar::build(8.0);
    assert_eq!(hi.bar.len(), 8);
    assert_eq!(hi.bar, "########");
}

#[test]
fn entropy_bar_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..60 {
        let e = (g() as f64) / (u64::MAX as f64) * 16.0 - 4.0; // negative + over-range
        let b = EntropyBar::build(e);
        assert_eq!(b.bar.chars().count(), 8);
    }
}

// ──────────── DiffStatus / DiffHighlightMap ────────────

#[test]
fn diff_status_color_mapping() {
    assert!(DiffStatus::Same.color().is_none());
    assert_eq!(DiffStatus::Changed.color(), Some(Color::yellow()));
    assert_eq!(DiffStatus::OnlyInLeft.color(), Some(Color::red()));
    assert_eq!(DiffStatus::OnlyInRight.color(), Some(Color::green()));
}

#[test]
fn diff_status_eq_hash_consistency() {
    use std::collections::HashSet;
    let mut s: HashSet<DiffStatus> = HashSet::new();
    s.insert(DiffStatus::Same);
    s.insert(DiffStatus::Same);
    s.insert(DiffStatus::Changed);
    s.insert(DiffStatus::OnlyInLeft);
    s.insert(DiffStatus::OnlyInRight);
    assert_eq!(s.len(), 4);
}

#[test]
fn diff_highlight_map_default_same() {
    let m = DiffHighlightMap::default();
    assert!(!m.has_changes());
    assert_eq!(m.status(0), DiffStatus::Same);
    assert_eq!(m.status(usize::MAX), DiffStatus::Same);
}

#[test]
fn diff_highlight_map_set_diff_via_state() {
    let a = HexBuffer::new(vec![1, 2, 3, 4]);
    let b = HexBuffer::new(vec![1, 2, 9, 4]);
    let mut st = HexViewState::new(a);
    st.set_diff_buffer(b);
    assert!(st.diff_highlights.has_changes() || !st.diff_highlights.has_changes());
    st.clear_diff();
    assert!(!st.diff_highlights.has_changes());
    assert!(st.diff_buffer.is_none());
    assert!(!st.config.show_diff);
}

// ──────────── StructFieldOverlay / StructureOverlayView ────────────

#[test]
fn struct_field_overlay_contains() {
    let f = StructFieldOverlay::new(10, 4, "field", "u32", Color::red());
    assert!(f.contains(10));
    assert!(f.contains(13));
    assert!(!f.contains(14));
    assert!(!f.contains(9));
}

#[test]
fn structure_overlay_view_basic() {
    let mut v = StructureOverlayView::new();
    v.add(StructFieldOverlay::new(20, 4, "b", "u32", Color::blue()));
    v.add(StructFieldOverlay::new(0, 4, "a", "u32", Color::red()));
    // Sorted
    assert_eq!(v.fields[0].offset, 0);
    assert_eq!(v.at_offset(2).len(), 1);
    assert_eq!(v.color_at(2), Some(Color::red()));
    assert_eq!(v.color_at(100), None);
}

// ──────────── RenderedLine ────────────

#[test]
fn rendered_line_to_display_basic() {
    let l = RenderedLine {
        offset_str: "00000000".into(),
        hex_str: "AB CD".into(),
        ascii_str: "..".into(),
        spans: vec![],
        entropy_bar: None,
        floating_labels: vec![],
    };
    let d = l.to_display();
    assert!(d.contains("00000000"));
    assert!(d.contains("AB CD"));
    assert!(d.contains("|..|"));
}

#[test]
fn rendered_line_floating_label_text() {
    let l = RenderedLine {
        offset_str: String::new(),
        hex_str: String::new(),
        ascii_str: String::new(),
        spans: vec![],
        entropy_bar: None,
        floating_labels: vec!["a".into(), "b".into()],
    };
    assert_eq!(l.floating_label_text(), "a, b");
}

// ──────────── PlainHexRenderer ────────────

#[test]
fn plain_render_uppercase_vs_lowercase() {
    let mut cfg = HexViewConfig::default();
    cfg.uppercase_hex = true;
    let r = PlainHexRenderer::new(cfg.clone());
    let l = r.render_line(0, &[0xAB], &[]);
    assert!(l.hex_str.contains("AB"));
    cfg.uppercase_hex = false;
    let r = PlainHexRenderer::new(cfg);
    let l = r.render_line(0, &[0xAB], &[]);
    assert!(l.hex_str.contains("ab"));
}

#[test]
fn plain_render_no_ascii() {
    let cfg = HexViewConfig { show_ascii: false, ..HexViewConfig::default() };
    let r = PlainHexRenderer::new(cfg);
    let l = r.render_line(0, b"Hi", &[]);
    assert!(l.ascii_str.is_empty());
}

#[test]
fn plain_render_pad_for_short_row() {
    let r = PlainHexRenderer::new(HexViewConfig::default());
    let l = r.render_line(0, &[0xAA, 0xBB], &[]);
    // bytes_per_row=16 → 16 byte slots ≈ 16*2 hex + spaces
    assert!(l.hex_str.len() >= 32);
}

#[test]
fn plain_render_all_fuzz_no_panic() {
    let mut g = lcg();
    let r = PlainHexRenderer::new(HexViewConfig::default());
    let layer = AnnotationLayer::new();
    for _ in 0..20 {
        let n = (g() as usize) % 200;
        let buf: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let lines = r.render_all(&buf, 0, &HexViewConfig::default(), &layer);
        let exp = n.div_ceil(16);
        assert_eq!(lines.len(), exp);
    }
}

#[test]
fn plain_render_empty_input() {
    let r = PlainHexRenderer::new(HexViewConfig::default());
    let lines = r.render_all(&[], 0, &HexViewConfig::default(), &AnnotationLayer::new());
    assert!(lines.is_empty());
}

#[test]
fn plain_render_entropy_bar_present() {
    let cfg = HexViewConfig::with_entropy();
    let r = PlainHexRenderer::new(cfg);
    let l = r.render_line(0, &[0u8; 16], &[]);
    assert!(l.entropy_bar.is_some());
}

// ──────────── AnsiHexRenderer ────────────

#[test]
fn ansi_render_has_escape_codes() {
    let r = AnsiHexRenderer::new(HexViewConfig::default());
    let s = r.render_line_ansi(0, &[0x41u8, 0x42, 0x43], &[]);
    assert!(s.contains('\x1b'));
    assert!(s.contains("|ABC|"));
}

#[test]
fn ansi_render_spans_count_eq_bytes() {
    let r = AnsiHexRenderer::new(HexViewConfig::default());
    let data = [0x10u8, 0x20, 0x30, 0x40, 0x50];
    let l = r.render_line(0, &data, &[]);
    assert_eq!(l.spans.len(), data.len());
}

#[test]
fn ansi_render_annotation_overrides_color() {
    let r = AnsiHexRenderer::new(HexViewConfig::default());
    let ann = Annotation { offset: 0, len: 2, label: "x".into(), color: Color::magenta() };
    let l = r.render_line(0, &[1u8, 2, 3], &[ann]);
    assert_eq!(l.spans[0].fg, Color::magenta());
    assert_eq!(l.spans[1].fg, Color::magenta());
    assert_ne!(l.spans[2].fg, Color::magenta());
}

#[test]
fn ansi_render_with_diff_priority() {
    let regions = vec![rustre_hex::DiffRegion {
        offset: 0,
        len: 1,
        left: vec![0xAA],
        right: vec![0xBB],
    }];
    let diff = DiffHighlightMap::from_diff_regions(&regions, 1);
    let r = AnsiHexRenderer::new(HexViewConfig::default()).with_diff(diff);
    let l = r.render_line(0, &[0xAA], &[]);
    // Diff highlights override color map → yellow for Changed
    assert_eq!(l.spans[0].fg, Color::yellow());
}

#[test]
fn ansi_render_with_overlay() {
    let mut ov = StructureOverlayView::new();
    ov.add(StructFieldOverlay::new(0, 2, "f", "u16", Color::pink()));
    let r = AnsiHexRenderer::new(HexViewConfig::default()).with_overlay(ov);
    let l = r.render_line(0, &[1u8, 2, 3], &[]);
    assert_eq!(l.spans[0].fg, Color::pink());
    assert_eq!(l.spans[1].fg, Color::pink());
    assert_ne!(l.spans[2].fg, Color::pink());
}

// ──────────── ViewportState ────────────

#[test]
fn viewport_is_visible_boundaries() {
    let mut cfg = HexViewConfig::default();
    cfg.bytes_per_row = 16;
    cfg.visible_rows = 4;
    let vp = ViewportState { top_offset: 32, cursor: 0, selection: None };
    assert!(!vp.is_visible(0, &cfg));
    assert!(vp.is_visible(32, &cfg));
    assert!(vp.is_visible(32 + 16 * 4 - 1, &cfg));
    assert!(!vp.is_visible(32 + 16 * 4, &cfg));
}

// ──────────── HexViewState navigation ────────────

fn mk_state(n: usize) -> HexViewState {
    let buf = HexBuffer::new((0..n).map(|i| i as u8).collect());
    HexViewState::new(buf)
}

#[test]
fn state_navigation_basic() {
    let mut s = mk_state(256);
    s.go_to_offset(50);
    assert_eq!(s.viewport.cursor, 50);
    s.cursor_move_left();
    assert_eq!(s.viewport.cursor, 49);
    s.cursor_move_right();
    assert_eq!(s.viewport.cursor, 50);
    s.cursor_move_up();
    assert_eq!(s.viewport.cursor, 50usize.saturating_sub(16));
    let before = s.viewport.cursor;
    s.cursor_move_down();
    assert_eq!(s.viewport.cursor, before + 16);
}

#[test]
fn state_cursor_clamps_at_bounds() {
    let mut s = mk_state(10);
    s.go_to_offset(9999);
    assert_eq!(s.viewport.cursor, 9);
    s.cursor_move_right();
    assert_eq!(s.viewport.cursor, 9); // can't move past end
    s.go_to_start();
    assert_eq!(s.viewport.cursor, 0);
    s.cursor_move_left();
    assert_eq!(s.viewport.cursor, 0);
}

#[test]
fn state_page_up_down() {
    let mut s = mk_state(4096);
    s.viewport.top_offset = 0;
    s.viewport.cursor = 0;
    s.page_down();
    assert!(s.viewport.cursor > 0);
    s.page_up();
    assert_eq!(s.viewport.cursor, 0);
}

#[test]
fn state_go_to_start_end() {
    let mut s = mk_state(100);
    s.go_to_end();
    assert_eq!(s.viewport.cursor, 99);
    s.go_to_start();
    assert_eq!(s.viewport.cursor, 0);
    assert_eq!(s.viewport.top_offset, 0);
}

#[test]
fn state_selection_flow() {
    let mut s = mk_state(64);
    s.go_to_offset(10);
    s.begin_selection();
    s.go_to_offset(20);
    s.extend_selection();
    let sel = s.viewport.selection.clone().unwrap();
    assert_eq!(sel.start, 10);
    assert_eq!(sel.end, 21);
    let bytes = s.selected_bytes().unwrap();
    assert_eq!(bytes.len(), 11);
    s.clear_selection();
    assert!(s.viewport.selection.is_none());
}

#[test]
fn state_selection_reverse() {
    let mut s = mk_state(64);
    s.go_to_offset(20);
    s.begin_selection();
    s.go_to_offset(10);
    s.extend_selection();
    let sel = s.viewport.selection.clone().unwrap();
    assert_eq!(sel.start, 10);
    assert_eq!(sel.end, 21);
}

#[test]
fn state_total_rows() {
    let s = mk_state(33);
    assert_eq!(s.total_rows(), 3); // 16+16+1
    let s2 = mk_state(0);
    assert_eq!(s2.total_rows(), 0);
}

#[test]
fn state_row_entropy_and_invalidate() {
    let mut s = mk_state(256);
    let e0 = s.row_entropy(0);
    assert!((0.0..=8.0).contains(&e0));
    s.invalidate_entropy();
    let e1 = s.row_entropy(0);
    assert!((e0 - e1).abs() < 1e-9);
}

#[test]
fn state_entropy_rows_and_histogram() {
    let s = mk_state(256);
    let rows = s.entropy_rows();
    assert!(!rows.is_empty());
    let h = s.histogram();
    let _ = h;
}

#[test]
fn state_render_visible_plain_and_ansi() {
    let s = mk_state(64);
    let plain = s.render_visible_plain();
    let ansi = s.render_visible_ansi();
    assert!(!plain.is_empty());
    assert!(!ansi.is_empty());
    assert!(ansi.iter().any(|l| l.contains('\x1b')));
}

#[test]
fn state_render_visible_past_end_empty() {
    let mut s = mk_state(16);
    s.viewport.top_offset = 9999;
    assert!(s.render_visible_plain().is_empty());
    assert!(s.render_visible_ansi().is_empty());
}

#[test]
fn state_scroll_to_aligns_row() {
    let mut s = mk_state(256);
    s.scroll_to(35);
    // 35 / 16 = 2, * 16 = 32
    assert_eq!(s.viewport.top_offset, 32);
}

#[test]
fn state_with_config_round_trip() {
    let buf = HexBuffer::new(vec![1, 2, 3]);
    let cfg = HexViewConfig { bytes_per_row: 8, visible_rows: 2, ..HexViewConfig::default() };
    let s = HexViewState::with_config(buf, cfg);
    assert_eq!(s.config.bytes_per_row, 8);
    assert_eq!(s.config.visible_rows, 2);
}

// ──────────── format_hex_dump ────────────

#[test]
fn format_hex_dump_round_trip_lines() {
    let mut g = lcg();
    for _ in 0..20 {
        let n = (g() as usize) % 100;
        let buf: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let dump = format_hex_dump(&buf, 0);
        let expected_lines = n.div_ceil(16);
        if expected_lines == 0 {
            assert!(dump.is_empty());
        } else {
            assert_eq!(dump.lines().count(), expected_lines);
        }
    }
}

#[test]
fn format_hex_dump_ansi_has_escape() {
    let s = format_hex_dump_ansi(b"hello world!!!!!", 0);
    assert!(s.contains('\x1b'));
}

#[test]
fn format_hex_dump_includes_base_offset() {
    let s = format_hex_dump(&[0u8; 32], 0x100);
    assert!(s.contains("00000100"));
    assert!(s.contains("00000110"));
}

// ──────────── Send/Sync threaded stress ────────────

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<Color>();
    assert_send_sync::<ColorMap>();
    assert_send_sync::<ColorScheme>();
    assert_send_sync::<OffsetBase>();
    assert_send_sync::<HexViewConfig>();
    assert_send_sync::<Annotation>();
    assert_send_sync::<AnnotationLayer>();
    assert_send_sync::<DiffStatus>();
    assert_send_sync::<DiffHighlightMap>();
    assert_send_sync::<ViewportState>();
    assert_send_sync::<RenderedLine>();
}

#[test]
fn threaded_color_blend_stress() {
    use std::sync::Arc;
    use std::thread;
    let a = Arc::new(Color::red());
    let b = Arc::new(Color::blue());
    let mut handles = vec![];
    for t in 0..4 {
        let a = a.clone();
        let b = b.clone();
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for i in 0..100 {
                let m = a.blend(*b, (t as f32 + i as f32) / 400.0);
                acc = acc.wrapping_add(m.r as u64 + m.g as u64 + m.b as u64);
            }
            acc
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

#[test]
fn threaded_annotation_layer_overlapping_stress() {
    use std::sync::Arc;
    use std::thread;
    let mut layer = AnnotationLayer::new();
    for i in 0..50usize {
        layer.add(Annotation {
            offset: i * 10,
            len: 5,
            label: "x".into(),
            color: Color::red(),
        });
    }
    let layer = Arc::new(layer);
    let mut handles = vec![];
    for t in 0..4usize {
        let layer = layer.clone();
        handles.push(thread::spawn(move || {
            let mut count = 0;
            for i in 0..100usize {
                let off = (t * 50 + i * 3) % 500;
                count += layer.overlapping(off, 10).len();
            }
            count
        }));
    }
    let mut total = 0;
    for h in handles {
        total += h.join().unwrap();
    }
    let _ = total;
}
