// ============================================================================
// ui/widgets/status_bar.rs
// ============================================================================

use crate::core::app_state::UIState;
use crate::ui::theme::{colors, sizes};
use gpui::{div, px, FontWeight, Hsla, IntoElement, ParentElement, Styled};

pub fn render_status_bar(ui: &UIState, fps: f32, analysis_progress: f32) -> impl IntoElement {
    let status_msg = ui.status_msg.as_ref().map_or("", |(m, t)| {
        if t.elapsed().as_secs() < 5 {
            m.as_str()
        } else {
            ""
        }
    });

    // Convert the 0.0..=1.0 progress fraction supplied by the analysis engine
    // into an integer percentage for the status-bar indicator. Clamped so a
    // mid-step value never overflows the 0..=100 display range.
    let pct_f = (analysis_progress.clamp(0.0, 1.0) * 100.0).round();
    let analysis_pct = pct_f as u32;

    div()
        .flex()
        .flex_row()
        .flex_shrink_0()
        .w_full()
        .h(px(sizes::STATUS_H))
        .bg(colors::bg_elevated())
        .border_t_1()
        .border_color(colors::border())
        .items_center()
        .px_3()
        .justify_between()
        .child(
            div()
                .flex()
                .flex_row()
                .gap_4()
                .items_center()
                .child(status_badge("Zyphora", colors::accent()))
                .child(
                    div()
                        .text_size(px(sizes::STATUS))
                        .text_color(colors::text_secondary())
                        .child(status_msg.to_owned()),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_4()
                .items_center()
                .child(
                    div()
                        .text_size(px(sizes::STATUS))
                        .text_color(colors::text_muted())
                        .child(format!("analysis {analysis_pct}%")),
                )
                .child(
                    div()
                        .text_size(px(sizes::STATUS))
                        .text_color(colors::text_muted())
                        .child(format!("{fps:.1} fps")),
                ),
        )
}

fn status_badge(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .px_1()
        .rounded_sm()
        .text_size(px(sizes::STATUS - 0.5))
        .text_color(color)
        .font_weight(FontWeight::BOLD)
        .child(label.to_owned())
}
