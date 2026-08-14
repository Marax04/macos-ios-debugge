// ============================================================================
// ui/widgets/icon.rs — SVG icon helper
//
// Renders Lucide-style stroked SVG icons from `assets/icons/<name>.svg`.
// All emojis throughout the UI have been replaced with calls to `icon()`.
// ============================================================================

use gpui::{svg, Hsla, IntoElement, SharedString, Styled, Svg};

use crate::ui::theme::colors;

/// Render the icon `name` (looked up at `assets/icons/<name>.svg`) at the
/// default 16 px size and with the current text colour as stroke.
pub fn icon(name: &'static str) -> Svg {
    icon_sized(name, 16.0, 16.0)
}

/// Render the icon `name` with an explicit pixel size.
pub fn icon_sized(name: &'static str, w_px: f32, h_px: f32) -> Svg {
    svg()
        .path(SharedString::from(format!("icons/{name}.svg")))
        .w(gpui::px(w_px))
        .h(gpui::px(h_px))
        .text_color(colors::text_secondary())
        .flex_none()
}

/// Render the icon `name` at the default size with a custom colour.
pub fn icon_colored(name: &'static str, color: Hsla) -> Svg {
    svg()
        .path(SharedString::from(format!("icons/{name}.svg")))
        .w(gpui::px(16.0))
        .h(gpui::px(16.0))
        .text_color(color)
        .flex_none()
}

#[doc(hidden)]
pub fn ensure_used_icon() {
    let _ = icon("settings").into_any_element();
    let _ = icon_sized("search", 14.0, 14.0).into_any_element();
    let _ = icon_colored("check", colors::accent()).into_any_element();
}
