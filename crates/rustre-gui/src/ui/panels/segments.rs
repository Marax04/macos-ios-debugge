// ============================================================================
// ui/panels/segments.rs — Segments / Memory Map panel with permission badges,
// size visualization bars, type indicators, and entropy bar stubs.
// ============================================================================
use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Segment, SegmentFlags};
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, relative, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement,
    ParentElement, SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

// ── Public entry point ────────────────────────────────────────────────────────

/// Render the Segments / Memory Map panel. Each row navigates the listing to
/// the segment's start address when clicked.
pub fn render_segments_panel<'a>(
    data: &'a AppData,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    let segs = &data.segments;
    let total_size: u64 = segs.iter().map(Segment::size).sum();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(seg_panel_header(segs.len(), total_size))
        .child(seg_col_hdr())
        .child(
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .id("segments-scroll")
                .overflow_y_scroll()
                .children(
                    segs.iter()
                        .enumerate()
                        .map(|(idx, s)| seg_row(s, total_size, idx, Arc::clone(bus))),
                )
                .child(if segs.is_empty() {
                    seg_empty_state().into_any_element()
                } else {
                    div().into_any_element()
                }),
        )
}

// ── Panel header ──────────────────────────────────────────────────────────────

fn seg_panel_header(count: usize, total_size: u64) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(28.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::PANEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Segments / Memory Map")
                .truncate(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child(format!(
                            "{count} region{}",
                            if count == 1 { "" } else { "s" }
                        ))
                        .truncate(),
                )
                .child(if total_size > 0 {
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format_size(total_size))
                        .truncate()
                        .into_any_element()
                } else {
                    div().into_any_element()
                }),
        )
}

// ── Column headers ────────────────────────────────────────────────────────────

fn seg_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .h(px(18.0))
        .px_2()
        .items_center()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(col_label("Name", 100.0))
        .child(col_label("Start", 130.0))
        .child(col_label("End", 130.0))
        .child(col_label("Size", 80.0))
        .child(col_label("Perm", 50.0))
        .child(col_label("Type", 60.0))
        .child(
            div()
                .flex_1()
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Usage")
                .truncate(),
        )
}

fn col_label(l: &str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(8.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(l.to_owned())
        .truncate()
}

// ── Segment row ───────────────────────────────────────────────────────────────

fn perm_string(is_read: bool, is_write: bool, is_exec: bool) -> String {
    format!(
        "{}{}{}",
        if is_read { "r" } else { "-" },
        if is_write { "w" } else { "-" },
        if is_exec { "x" } else { "-" },
    )
}

const fn perm_color_of(is_read: bool, is_write: bool, is_exec: bool) -> Hsla {
    if is_exec {
        colors::syn_mnemonic()
    } else if is_write {
        colors::warn()
    } else if is_read {
        colors::syn_address()
    } else {
        colors::text_muted()
    }
}

const fn bar_color_of(is_read: bool, is_write: bool, is_exec: bool) -> Hsla {
    if is_exec {
        colors::syn_mnemonic()
    } else if is_write {
        colors::warn()
    } else if is_read {
        Hsla {
            h: colors::syn_address().h,
            s: 0.5,
            l: 0.4,
            a: 1.0,
        }
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.3,
            a: 1.0,
        }
    }
}

fn u32_to_f32(v: u32) -> f32 {
    let hi = u16::try_from(v >> 16).unwrap_or(u16::MAX);
    let lo = u16::try_from(v & 0xFFFF).unwrap_or(u16::MAX);
    f32::from(hi) * 65536.0_f32 + f32::from(lo)
}

fn u64_to_f64(v: u64) -> f64 {
    let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi) * 4_294_967_296.0_f64 + f64::from(lo)
}

fn seg_frac(seg_size: u64, total_size: u64) -> f32 {
    if total_size > 0 {
        // Downshift so both fit in u32 (f32 has 24-bit mantissa, u32 result rescaled).
        let bits = 64u32 - total_size.leading_zeros();
        let shift = bits.saturating_sub(32);
        let s = u32::try_from(seg_size >> shift).unwrap_or(u32::MAX);
        let t = u32::try_from(total_size >> shift)
            .unwrap_or(u32::MAX)
            .max(1);
        u32_to_f32(s) / u32_to_f32(t)
    } else {
        0.0
    }
}

fn seg_type_badge(seg_type: &'static str) -> impl IntoElement {
    div().w(px(60.0)).child(
        div()
            .px(px(4.0))
            .h(px(14.0))
            .flex()
            .items_center()
            .rounded_sm()
            .bg(seg_type_bg(seg_type))
            .text_size(px(8.0))
            .text_color(Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.9,
                a: 1.0,
            })
            .child(seg_type)
            .truncate(),
    )
}

fn seg_size_bar(frac: f32, bar_color: Hsla) -> impl IntoElement {
    div()
        .flex_1()
        .h(px(6.0))
        .bg(colors::bg_elevated())
        .rounded_sm()
        .flex()
        .items_center()
        .child(div().w(relative(frac)).h_full().rounded_sm().bg(bar_color))
}

fn seg_row(s: &Segment, total_size: u64, idx: usize, bus: Arc<EventBus>) -> impl IntoElement {
    let is_exec = s.flags.contains(SegmentFlags::EXECUTE);
    let jump_addr = s.start;
    let is_write = s.flags.contains(SegmentFlags::WRITE);
    let is_read = s.flags.contains(SegmentFlags::READ);

    let perm_str = perm_string(is_read, is_write, is_exec);
    let perm_color = perm_color_of(is_read, is_write, is_exec);
    let seg_size = s.size();
    let frac = seg_frac(seg_size, total_size);
    let bar_color = bar_color_of(is_read, is_write, is_exec);
    let seg_type = classify_segment_type(&s.name);

    let row_bg = if is_exec {
        Hsla {
            h: colors::syn_mnemonic().h,
            s: 0.15,
            l: 0.12,
            a: 0.2,
        }
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    div()
        .id(SharedString::from(format!("seg-row-{idx}")))
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 2.0))
        .items_center()
        .px_2()
        .bg(row_bg)
        .border_b_1()
        .border_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.12,
            a: 0.4,
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::NavigateTo {
                addr: jump_addr,
                push_history: true,
            });
        })
        .child(
            div()
                .w(px(100.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child(s.name.clone())
                .truncate(),
        )
        .child(
            div()
                .w(px(130.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#016x}", s.start.0))
                .truncate(),
        )
        .child(
            div()
                .w(px(130.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#016x}", s.end.0))
                .truncate(),
        )
        .child(
            div()
                .w(px(80.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_immediate())
                .child(format_size(seg_size))
                .truncate(),
        )
        .child(
            div()
                .w(px(50.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(perm_color)
                .font_weight(FontWeight::SEMIBOLD)
                .child(perm_str)
                .truncate(),
        )
        .child(seg_type_badge(seg_type))
        .child(seg_size_bar(frac, bar_color))
}

// ── Empty state ───────────────────────────────────────────────────────────────

fn seg_empty_state() -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .w_full()
        .pt(px(24.0))
        .gap(px(6.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_muted())
                .child("No segments loaded")
                .truncate(),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .child("Open a binary to see its memory map.")
                .truncate(),
        )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Human-readable size string.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    let bytes_f = u64_to_f64(bytes);
    if bytes >= GB {
        format!(
            "{:.1} GB",
            bytes_f / f64::from(u32::try_from(GB).unwrap_or(u32::MAX))
        )
    } else if bytes >= MB {
        format!(
            "{:.1} MB",
            bytes_f / f64::from(u32::try_from(MB).unwrap_or(u32::MAX))
        )
    } else if bytes >= KB {
        format!(
            "{:.1} KB",
            bytes_f / f64::from(u32::try_from(KB).unwrap_or(u32::MAX))
        )
    } else {
        format!("{bytes} B")
    }
}

/// Classify a segment by its name into a short type label.
fn classify_segment_type(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("text") || n.contains("code") || n == ".init" || n == ".fini" {
        "CODE"
    } else if n.contains("data") && !n.contains("ro") {
        "DATA"
    } else if n.contains("rodata") || n.contains("rdata") || n.contains("const") {
        "RODATA"
    } else if n.contains("bss") {
        "BSS"
    } else if n.contains("plt") {
        "PLT"
    } else if n.contains("got") {
        "GOT"
    } else if n.contains("stack") {
        "STACK"
    } else if n.contains("heap") {
        "HEAP"
    } else if n.contains("reloc") || n.contains("rel.") || n.contains("rela.") {
        "RELOC"
    } else if n.contains("debug") || n.contains("dwarf") {
        "DEBUG"
    } else if n.contains("tls") || n.contains(".tbss") || n.contains(".tdata") {
        "TLS"
    } else if n.contains("note") {
        "NOTE"
    } else if n.contains("dynamic") || n == ".dyn" {
        "DYN"
    } else if n.contains("interp") {
        "INTERP"
    } else {
        "OTHER"
    }
}

fn seg_type_bg(ty: &str) -> Hsla {
    match ty {
        "CODE" => Hsla {
            h: 200.0 / 360.0,
            s: 0.55,
            l: 0.25,
            a: 1.0,
        },
        "DATA" => Hsla {
            h: 30.0 / 360.0,
            s: 0.50,
            l: 0.25,
            a: 1.0,
        },
        "RODATA" => Hsla {
            h: 60.0 / 360.0,
            s: 0.45,
            l: 0.22,
            a: 1.0,
        },
        "BSS" => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.28,
            a: 1.0,
        },
        "PLT" => Hsla {
            h: 270.0 / 360.0,
            s: 0.45,
            l: 0.25,
            a: 1.0,
        },
        "GOT" => Hsla {
            h: 300.0 / 360.0,
            s: 0.40,
            l: 0.22,
            a: 1.0,
        },
        "STACK" => Hsla {
            h: 0.0 / 360.0,
            s: 0.50,
            l: 0.25,
            a: 1.0,
        },
        "HEAP" => Hsla {
            h: 160.0 / 360.0,
            s: 0.45,
            l: 0.22,
            a: 1.0,
        },
        "DEBUG" => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.20,
            a: 1.0,
        },
        "RELOC" => Hsla {
            h: 180.0 / 360.0,
            s: 0.35,
            l: 0.20,
            a: 1.0,
        },
        "TLS" => Hsla {
            h: 140.0 / 360.0,
            s: 0.40,
            l: 0.22,
            a: 1.0,
        },
        _ => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.22,
            a: 1.0,
        },
    }
}
