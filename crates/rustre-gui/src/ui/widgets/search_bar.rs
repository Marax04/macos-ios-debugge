// ============================================================================
// ui/widgets/search_bar.rs
// ============================================================================
use crate::ui::theme::{colors, sizes};
use gpui::InteractiveElement;
use gpui::{div, px, IntoElement, ParentElement, Styled};

pub fn render_search_bar(query: &str, result_count: usize, current_idx: usize) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .h(px(30.0))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(12.0))
                .text_color(colors::text_muted())
                .child(crate::ui::widgets::icon::icon("search")),
        )
        .child(
            div()
                .flex()
                .flex_1()
                .h(px(22.0))
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border_focus())
                .rounded_sm()
                .px_2()
                .items_center()
                .text_size(px(sizes::CODE))
                .text_color(colors::text_primary())
                .font_family("JetBrains Mono")
                .child(if query.is_empty() {
                    "Search…".to_owned()
                } else {
                    query.to_owned()
                }),
        )
        .child(
            div()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .child(if result_count > 0 {
                    format!("{}/{}", current_idx + 1, result_count)
                } else {
                    "No results".into()
                }),
        )
        .child(nav_btn("^"))
        .child(nav_btn("v"))
}

fn nav_btn(s: &str) -> impl IntoElement {
    div()
        .w(px(20.0))
        .h(px(20.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_sm()
        .cursor_pointer()
        .text_size(px(10.0))
        .text_color(colors::text_secondary())
        .hover(|s| s.bg(colors::bg_hover()))
        .child(s.to_owned())
}

#[doc(hidden)]
pub fn ensure_used_search_bar() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let _ = render_search_bar("", 0, 0);
    let _ = nav_btn("^");
}
