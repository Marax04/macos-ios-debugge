//! Blitz test suite for rustre-hex-view public API.
//! Tests target public surface (lib.rs top-level) for boundary/edge cases.

use rustre_hex::HexBuffer;
use rustre_hex_view::*;
use std::ops::Range;

// ────────── Color ──────────

#[test]
fn blitz_color_blend_t_clamped_high() {
    let a = Color::black();
    let b = Color::white();
    // t > 1.0 should clamp to 1.0
    let c = a.blend(b, 2.0);
    assert_eq!(c, Color::white());
}

#[test]
fn blitz_color_blend_t_clamped_low() {
    let a = Color::black();
    let b = Color::white();
    let c = a.blend(b, -1.0);
    assert_eq!(c, Color::black());
}

#[test]
fn blitz_color_from_rgb_u32_truncates_high_bits() {
    let c = Color::from_rgb_u32(0xFFAABBCC);
    // top byte ignored
    assert_eq!(c, Color::new(0xAA, 0xBB, 0xCC));
}

#[test]
fn blitz_color_for_entropy_negative_clamps() {
    let c = Color::for_entropy(-5.0);
    // Should clamp to t=0 → blend(blue, green, 0) = blue
    assert_eq!(c, Color::blue());
}

#[test]
fn blitz_color_ansi_fg_format() {
    assert_eq!(Color::new(1, 2, 3).ansi_fg(), "\x1b[38;2;1;2;3m");
}

// ────────── OffsetBase ──────────

#[test]
fn blitz_offset_octal_format() {
    let s = OffsetBase::Octal.format(64);
    // 64 decimal = 100 octal; format!("{:011o}", 64) = "00000000100"
    assert_eq!(s, "00000000100");
}

#[test]
fn blitz_offset_decimal_zero_pad() {
    assert_eq!(OffsetBase::Decimal.format(7), "0000000007");
}

#[test]
fn blitz_offset_prefixed_octal() {
    assert!(OffsetBase::Octal.format_prefixed(8).starts_with("0o"));
}

// ────────── ColorMap ──────────

#[test]
fn blitz_colormap_add_range_and_lookup() {
    let mut cm = ColorMap {
        ranges: vec![],
        default_fg: Color::white(),
        default_bg: None,
    };
    cm.add_range(0x10, 0x1F, Color::red(), Some(Color::black()));
    let (fg, bg) = cm.lookup(0x15);
    assert_eq!(fg, Color::red());
    assert_eq!(bg, Some(Color::black()));
    // outside falls back to default
    let (fg2, _) = cm.lookup(0x20);
    assert_eq!(fg2, Color::white());
}

// ────────── Annotation ──────────

#[test]
fn blitz_annotation_range() {
    let a = Annotation {
        offset: 10,
        len: 5,
        label: "x".into(),
        color: Color::red(),
    };
    assert_eq!(a.range(), 10..15);
}

#[test]
fn blitz_annotation_overlaps_adjacent_is_false() {
    let a = Annotation {
        offset: 0,
        len: 5,
        label: "a".into(),
        color: Color::red(),
    };
    // adjacent range starting exactly at end should NOT overlap
    assert!(!a.overlaps(5..10));
    assert!(a.overlaps(4..6));
}

// ────────── AnnotationLayer remove_in_range ──────────

#[test]
fn blitz_annotation_layer_remove_in_range() {
    let mut layer = AnnotationLayer::new();
    layer.add(Annotation { offset: 0, len: 5, label: "a".into(), color: Color::red() });
    layer.add(Annotation { offset: 20, len: 5, label: "b".into(), color: Color::red() });
    layer.remove_in_range(0..10);
    assert_eq!(layer.len(), 1);
    assert_eq!(layer.annotations[0].label, "b");
}

#[test]
fn blitz_annotation_layer_at_offset() {
    let mut layer = AnnotationLayer::new();
    layer.add(Annotation { offset: 5, len: 1, label: "x".into(), color: Color::red() });
    layer.add(Annotation { offset: 5, len: 2, label: "y".into(), color: Color::red() });
    assert_eq!(layer.at_offset(5).len(), 2);
    assert_eq!(layer.at_offset(6).len(), 0);
}

// ────────── DiffHighlightMap ──────────

#[test]
fn blitz_diff_highlight_only_in_left() {
    use rustre_hex::DiffRegion;
    let regions = vec![DiffRegion {
        offset: 0,
        len: 3,
        left: vec![1, 2, 3],
        right: vec![1],
    }];
    let dm = DiffHighlightMap::from_diff_regions(&regions, 10);
    assert_eq!(dm.status(0), DiffStatus::Changed);
    assert_eq!(dm.status(1), DiffStatus::OnlyInLeft);
    assert_eq!(dm.status(2), DiffStatus::OnlyInLeft);
}

#[test]
fn blitz_diff_highlight_only_in_right() {
    use rustre_hex::DiffRegion;
    let regions = vec![DiffRegion {
        offset: 0,
        len: 3,
        left: vec![1],
        right: vec![1, 2, 3],
    }];
    let dm = DiffHighlightMap::from_diff_regions(&regions, 10);
    assert_eq!(dm.status(0), DiffStatus::Changed);
    assert_eq!(dm.status(1), DiffStatus::OnlyInRight);
    assert_eq!(dm.status(2), DiffStatus::OnlyInRight);
}

#[test]
fn blitz_diff_status_colors() {
    assert!(DiffStatus::Same.color().is_none());
    assert!(DiffStatus::Changed.color().is_some());
    assert!(DiffStatus::OnlyInLeft.color().is_some());
    assert!(DiffStatus::OnlyInRight.color().is_some());
}

// ────────── HexViewState navigation edge cases ──────────

fn buf256() -> HexBuffer {
    HexBuffer::new((0u8..=255).collect())
}

#[test]
fn blitz_go_to_offset_clamped_past_end() {
    let mut s = HexViewState::new(buf256());
    s.go_to_offset(999_999);
    assert_eq!(s.viewport.cursor, 255);
}

#[test]
fn blitz_empty_buffer_navigation_no_panic() {
    let mut s = HexViewState::new(HexBuffer::new(vec![]));
    s.cursor_move_left();
    s.cursor_move_right();
    s.cursor_move_up();
    s.cursor_move_down();
    s.page_up();
    s.page_down();
    s.go_to_start();
    s.go_to_end();
    s.go_to_offset(42);
    // No assertion: must not panic.
}

#[test]
fn blitz_total_rows_empty_buffer() {
    let s = HexViewState::new(HexBuffer::new(vec![]));
    assert_eq!(s.total_rows(), 0);
}

#[test]
fn blitz_selected_bytes_none_when_no_selection() {
    let s = HexViewState::new(buf256());
    assert!(s.selected_bytes().is_none());
}

#[test]
fn blitz_render_visible_plain_returns_lines() {
    let s = HexViewState::new(HexBuffer::new(vec![0xAB; 64]));
    let lines = s.render_visible_plain();
    assert!(!lines.is_empty());
}

#[test]
fn blitz_render_visible_ansi_empty_buffer() {
    let s = HexViewState::new(HexBuffer::new(vec![]));
    assert!(s.render_visible_ansi().is_empty());
}

#[test]
fn blitz_clear_diff_resets_state() {
    let mut s = HexViewState::new(HexBuffer::new(vec![1, 2, 3]));
    s.set_diff_buffer(HexBuffer::new(vec![1, 9, 3]));
    assert!(s.config.show_diff);
    s.clear_diff();
    assert!(!s.config.show_diff);
    assert!(s.diff_buffer.is_none());
}

#[test]
fn blitz_entropy_rows_and_invalidate() {
    let mut s = HexViewState::new(HexBuffer::new(vec![0u8; 64]));
    let rows = s.entropy_rows();
    assert!(!rows.is_empty());
    let e = s.row_entropy(0);
    assert!((e - 0.0).abs() < 1e-9);
    s.invalidate_entropy();
    let _ = s.row_entropy(0);
}

// ────────── ViewportState ──────────

#[test]
fn blitz_viewport_is_visible_boundary() {
    let vp = ViewportState { top_offset: 16, cursor: 0, selection: None };
    let cfg = HexViewConfig::default();
    assert!(!vp.is_visible(15, &cfg));
    assert!(vp.is_visible(16, &cfg));
}

// ────────── MiniMap ──────────

#[test]
fn blitz_minimap_empty_data() {
    let mm = MiniMap::build(&[], 4, 4, None, &[]);
    assert_eq!(mm.len(), 16);
    // bytes_per_cell computed from max(1)
    assert_eq!(mm.bytes_per_cell, 1);
}

#[test]
#[should_panic(expected = "MiniMap")]
fn blitz_minimap_zero_width_panics() {
    let _ = MiniMap::build(&[1, 2, 3], 0, 4, None, &[]);
}

#[test]
fn blitz_minimap_cell_at_oob() {
    let mm = MiniMap::build(&[0; 4], 2, 2, None, &[]);
    assert!(mm.cell_at(99, 99).is_none());
}

#[test]
fn blitz_minimap_offset_to_cell_roundtrip() {
    let mm = MiniMap::build(&[0u8; 256], 16, 16, None, &[]);
    let idx = mm.offset_to_cell(100);
    let off = mm.cell_to_offset(idx);
    assert!(off <= 100);
}

#[test]
fn blitz_minimap_high_byte_classification() {
    let data = vec![0xE0u8; 16];
    let mm = MiniMap::build(&data, 4, 4, None, &[]);
    assert!(mm.cells.iter().all(|c| *c == MiniMapCell::High));
}

#[test]
fn blitz_minimap_control_byte_classification() {
    let data = vec![0x01u8; 16];
    let mm = MiniMap::build(&data, 4, 4, None, &[]);
    assert!(mm.cells.iter().all(|c| *c == MiniMapCell::Control));
}

#[test]
fn blitz_minimap_cell_is_data() {
    assert!(!MiniMapCell::Null.is_data());
    assert!(MiniMapCell::Printable.is_data());
    assert!(MiniMapCell::High.is_data());
}

// ────────── RulerBase / build_ruler ──────────

#[test]
fn blitz_build_ruler_exact_multiple() {
    let labels = build_ruler(32, 16, RulerBase::Hex, 4);
    assert_eq!(labels.len(), 2);
}

#[test]
fn blitz_build_ruler_partial_row() {
    let labels = build_ruler(20, 16, RulerBase::Hex, 4);
    // 0 and 16 both < 20
    assert_eq!(labels.len(), 2);
}

#[test]
#[should_panic(expected = "build_ruler")]
fn blitz_build_ruler_zero_columns_panics() {
    let _ = build_ruler(10, 0, RulerBase::Hex, 4);
}

// ────────── ColumnHeader ──────────

#[test]
#[should_panic(expected = "build_column_header")]
fn blitz_column_header_zero_panics() {
    let _ = build_column_header(0);
}

#[test]
fn blitz_column_header_count_32() {
    let h = build_column_header(32);
    assert_eq!(h.split_whitespace().count(), 32);
}

// ────────── SearchHighlight ──────────

#[test]
fn blitz_search_highlight_focused_builder() {
    let h = SearchHighlight::new(0, 5).focused();
    assert!(h.is_focused);
    assert_eq!(h.end(), 5);
}

#[test]
fn blitz_search_layer_focus_prev_wraps() {
    let mut layer = SearchHighlightLayer::from_matches(&[(0, 1), (5, 1), (10, 1)]);
    layer.set_focus(0);
    layer.focus_prev();
    assert_eq!(layer.focused_index, Some(2));
}

#[test]
fn blitz_search_layer_empty_focus_noop() {
    let mut layer = SearchHighlightLayer::new();
    layer.focus_next();
    layer.focus_prev();
    assert!(layer.focused().is_none());
}

#[test]
fn blitz_search_layer_set_focus_oob_ignored() {
    let mut layer = SearchHighlightLayer::from_matches(&[(0, 1)]);
    layer.set_focus(99);
    // focus_index remains None since 99 >= len
    assert!(layer.focused_index.is_none());
}

// ────────── BookmarkView ──────────

#[test]
fn blitz_bookmark_view_remove_missing() {
    let mut bv = BookmarkView::new();
    bv.add(BookmarkEntry::new(0, "a"));
    assert!(!bv.remove("zzz"));
    assert_eq!(bv.len(), 1);
}

#[test]
fn blitz_bookmark_entry_with_color() {
    let e = BookmarkEntry::new(10, "x").with_color(Color::red());
    assert_eq!(e.color, Some(Color::red()));
}

#[test]
fn blitz_bookmark_view_near_zero_tolerance() {
    let mut bv = BookmarkView::new();
    bv.add(BookmarkEntry::new(100, "a"));
    assert_eq!(bv.near(100, 0).len(), 1);
    assert_eq!(bv.near(101, 0).len(), 0);
}

// ────────── SelectionStats ──────────

#[test]
fn blitz_selection_stats_mode_correct() {
    let data = vec![1u8, 1, 1, 2, 3];
    let s = SelectionStats::compute(&data).unwrap();
    assert_eq!(s.mode, (1, 3));
    assert_eq!(s.distinct, 3);
    assert_eq!(s.min, 1);
    assert_eq!(s.max, 3);
    assert_eq!(s.sum, 8);
}

#[test]
fn blitz_selection_stats_mean() {
    let s = SelectionStats::compute(&[2, 4, 6, 8]).unwrap();
    assert!((s.mean - 5.0).abs() < 1e-9);
}

// ────────── HexFindBar ──────────

#[test]
fn blitz_findbar_default_eq_new() {
    let a = HexFindBar::default();
    let b = HexFindBar::new();
    assert_eq!(a.query, b.query);
    assert_eq!(a.match_count, b.match_count);
}

#[test]
fn blitz_findbar_set_query_resets_matches() {
    let mut fb = HexFindBar::new();
    fb.set_results(5);
    fb.set_query("abc");
    assert_eq!(fb.match_count, 0);
    assert!(fb.focused_match.is_none());
}

#[test]
fn blitz_findbar_no_wrap_next_stops() {
    let mut fb = HexFindBar::new();
    fb.wrap = false;
    fb.set_results(2);
    fb.next_match(); // 0 -> 1
    fb.next_match(); // stays at 1 (no wrap)
    assert_eq!(fb.focused_match, Some(1));
}

#[test]
fn blitz_findbar_no_wrap_prev_stops() {
    let mut fb = HexFindBar::new();
    fb.wrap = false;
    fb.set_results(2);
    fb.prev_match(); // at 0, no wrap -> stays
    assert_eq!(fb.focused_match, Some(0));
}

#[test]
fn blitz_findbar_status_text_more_results_no_focus() {
    let mut fb = HexFindBar::new();
    fb.set_results(3);
    fb.focused_match = None;
    assert_eq!(fb.status_text(), "3 results");
}

// ────────── PaletteHighlight ──────────

#[test]
fn blitz_palette_highlight_empty_data() {
    let ph = PaletteHighlight::new(ColorScheme::Light);
    assert!(ph.spans(&[]).is_empty());
}

#[test]
fn blitz_palette_highlight_default_max() {
    let ph = PaletteHighlight::new(ColorScheme::Dark);
    assert_eq!(ph.max_bytes, 65536);
}

// ────────── HexStatusBar ──────────

#[test]
fn blitz_status_bar_no_byte_at_oob_cursor() {
    let buf = HexBuffer::new(vec![]);
    let state = HexViewState::new(buf);
    let sb = HexStatusBar::from_state(&state);
    assert!(sb.byte_value.is_none());
    let s = sb.render();
    assert!(s.contains("Size: 0"));
}

// ────────── RowMetrics ──────────

#[test]
fn blitz_row_metrics_col_in_separator() {
    let cfg = HexViewConfig::default();
    let m = RowMetrics::compute(0, 16, &cfg);
    // The byte at col 10..12, sep at 12, next byte at 13.
    // col_to_offset(12): rel=2, byte_idx=0 (2/3=0) → Some(0). Separator collapses.
    assert!(m.col_to_offset(12).is_some());
}

#[test]
fn blitz_row_metrics_far_past_end() {
    let cfg = HexViewConfig::default();
    let m = RowMetrics::compute(0, 4, &cfg);
    assert!(m.col_to_offset(1000).is_none());
}

// ────────── GroupSize ──────────

#[test]
fn blitz_group_size_bytes() {
    assert_eq!(GroupSize::None.bytes(), 1);
    assert_eq!(GroupSize::Two.bytes(), 2);
    assert_eq!(GroupSize::Four.bytes(), 4);
    assert_eq!(GroupSize::Eight.bytes(), 8);
}

#[test]
fn blitz_group_size_group_partial_last() {
    let data = [1u8, 2, 3, 4, 5];
    let groups = GroupSize::Two.group(&data);
    assert_eq!(groups.len(), 3);
    assert_eq!(groups.last().unwrap().len(), 1);
}

// ────────── HexRenderOptions ──────────

#[test]
fn blitz_hex_render_options_default() {
    let o = HexRenderOptions::default();
    assert_eq!(o.bytes_per_row, 16);
    assert!(o.show_ascii);
}

#[test]
fn blitz_hex_render_options_hex_columns_positive() {
    let o = HexRenderOptions::default();
    let c = o.hex_columns();
    assert!(c > 0);
}

// ────────── EntropyBar ──────────

#[test]
fn blitz_entropy_bar_color_changes() {
    let low = EntropyBar::build(0.0);
    let high = EntropyBar::build(8.0);
    assert_ne!(low.color, high.color);
}

// ────────── ColorSpan ──────────

#[test]
fn blitz_color_span_fg_ctor() {
    let s = ColorSpan::fg(0, 4, Color::red());
    assert_eq!(s.start, 0);
    assert_eq!(s.end, 4);
    assert!(!s.bold);
    assert!(!s.underline);
    assert!(s.bg.is_none());
}

// ────────── StructFieldOverlay ──────────

#[test]
fn blitz_struct_overlay_contains_boundary() {
    let f = StructFieldOverlay::new(10, 4, "x", "u32", Color::red());
    assert!(f.contains(10));
    assert!(f.contains(13));
    assert!(!f.contains(14));
    assert!(!f.contains(9));
}

#[test]
fn blitz_struct_overlay_color_at() {
    let mut ov = StructureOverlayView::new();
    ov.add(StructFieldOverlay::new(0, 4, "m", "u32", Color::yellow()));
    assert_eq!(ov.color_at(2), Some(Color::yellow()));
    assert!(ov.color_at(10).is_none());
}

// ────────── format_hex_dump_ansi ──────────

#[test]
fn blitz_format_hex_dump_ansi_contains_escape() {
    let d = [0xAA, 0xBB];
    let s = format_hex_dump_ansi(&d, 0);
    assert!(s.contains('\x1b'));
}

// ────────── HexViewConfig presets ──────────

#[test]
fn blitz_hex_view_config_for_diff() {
    let c = HexViewConfig::for_diff();
    assert!(c.show_diff);
}

#[test]
fn blitz_hex_view_config_with_entropy() {
    let c = HexViewConfig::with_entropy();
    assert!(c.show_entropy_bar);
}

// ────────── FloatingAnnotation ──────────

#[test]
fn blitz_floating_annotation_new() {
    let f = FloatingAnnotation::new(42, "hi", Color::cyan(), true);
    assert_eq!(f.offset, 42);
    assert_eq!(f.text, "hi");
    assert!(f.inline);
}

// ────────── RenderedLine ──────────

#[test]
fn blitz_rendered_line_floating_label_text() {
    let mut rl = RenderedLine {
        offset_str: String::new(),
        hex_str: String::new(),
        ascii_str: String::new(),
        spans: vec![],
        entropy_bar: None,
        floating_labels: vec!["a".into(), "b".into()],
    };
    assert_eq!(rl.floating_label_text(), "a, b");
    rl.floating_labels.clear();
    assert_eq!(rl.floating_label_text(), "");
}

// ────────── HexViewState page navigation correctness ──────────

#[test]
fn blitz_page_down_does_not_exceed_buffer() {
    let mut s = HexViewState::new(HexBuffer::new(vec![0u8; 64]));
    for _ in 0..20 {
        s.page_down();
    }
    assert!(s.viewport.cursor < 64);
}

// ────────── Range overlap sanity in AnnotationLayer ──────────

#[test]
fn blitz_overlapping_zero_len_query() {
    let mut layer = AnnotationLayer::new();
    layer.add(Annotation { offset: 5, len: 5, label: "z".into(), color: Color::red() });
    // zero-len query at 5 — end == start, no overlap expected
    let hits: Vec<&Annotation> = layer.overlapping(5, 0);
    // a.offset < 5 (end) is false (5 < 5 == false), so no hits
    assert_eq!(hits.len(), 0);
    let _ = Range { start: 0, end: 0 };
}
