// ============================================================================
// ui/widgets/toolbar.rs — Top toolbar with SVG icon buttons and click handlers
// Icons: Lucide (MIT) — embedded via assets/icons/*.svg
// ============================================================================

use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, svg, App, ClickEvent, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled, Window,
};

// ── Icon helper ───────────────────────────────────────────────────────────────

/// Renders a Lucide SVG icon at the given size.
/// `name` is the icon filename without extension, e.g. "folder-open".
pub fn icon(name: &str, size: f32) -> impl IntoElement {
    let path = format!("icons/{name}.svg");
    svg()
        .path(SharedString::from(path))
        .size(px(size))
        .flex_shrink_0()
        .text_color(colors::text_secondary())
}

/// Same as `icon()` but with an explicit color.
pub fn icon_color(name: &str, size: f32, color: Hsla) -> impl IntoElement {
    let path = format!("icons/{name}.svg");
    svg()
        .path(SharedString::from(path))
        .size(px(size))
        .flex_shrink_0()
        .text_color(color)
}

// ── Toolbar button ────────────────────────────────────────────────────────────

pub fn toolbar_button(label: &str, icon_name: &str, _tooltip: &str) -> impl IntoElement {
    div()
        .id(SharedString::from(label.to_owned()))
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap(px(2.0))
        .w(px(44.0))
        .h_full()
        .rounded_sm()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .child(icon(icon_name, 15.0))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .child(label.to_owned()),
        )
}

/// Toolbar button with a click handler.
pub fn toolbar_btn(
    label: &'static str,
    icon_name: &'static str,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("tb-{label}")))
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap(px(2.0))
        .w(px(44.0))
        .h_full()
        .rounded_sm()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .on_click(on_click)
        .child(icon(icon_name, 15.0))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .child(label),
        )
}

pub fn toolbar_button_wide(label: &str, icon_name: &str) -> impl IntoElement {
    div()
        .id(SharedString::from(label.to_owned()))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .px(px(6.0))
        .h_full()
        .rounded_sm()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .child(icon(icon_name, 14.0))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(label.to_owned()),
        )
}

pub fn toolbar_separator() -> impl IntoElement {
    div()
        .w(px(1.0))
        .h(px(20.0))
        .bg(colors::border())
        .mx(px(4.0))
}

// ── Main toolbar ──────────────────────────────────────────────────────────────

/// Boxed click handler used by toolbar buttons.
pub type ToolbarHandler = Box<dyn Fn(&ClickEvent, &mut Window, &mut App) + 'static>;

/// Fixed-size array of toolbar handlers, one per button.
pub type ToolbarHandlers = [ToolbarHandler; 14];

/// Render the toolbar with click handlers.
///
/// Each handler corresponds to a button in order:
/// [open, save, analyze, decompile, graph, run, `step_in`, `step_over`,
///  `step_out`, break_, back, forward, find, settings]
pub fn render_toolbar(handlers: ToolbarHandlers) -> impl IntoElement {
    let [h_open, h_save, h_analyze, h_decompile, h_graph, h_run, h_step_in, h_step_over, h_step_out, h_break, h_back, h_forward, h_find, h_settings] =
        handlers;

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::TOOLBAR_H))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .items_center()
        .px_2()
        // ── File group ───────────────────────────────────────────────────────
        .child(toolbar_btn("Open", "folder-open", h_open))
        .child(toolbar_btn("Save", "save", h_save))
        .child(toolbar_separator())
        // ── Analysis group ───────────────────────────────────────────────────
        .child(toolbar_btn("Analyze", "search", h_analyze))
        .child(toolbar_btn("Decompile", "code-2", h_decompile))
        .child(toolbar_btn("Graph", "git-branch", h_graph))
        .child(toolbar_separator())
        // ── Debug group ──────────────────────────────────────────────────────
        .child(toolbar_btn("Run", "play", h_run))
        .child(toolbar_btn("Step In", "arrow-down-left", h_step_in))
        .child(toolbar_btn("Step Over", "skip-forward", h_step_over))
        .child(toolbar_btn("Step Out", "corner-up-left", h_step_out))
        .child(toolbar_btn("Break", "pause", h_break))
        .child(toolbar_separator())
        // ── Navigation group ─────────────────────────────────────────────────
        .child(toolbar_btn("Back", "arrow-left", h_back))
        .child(toolbar_btn("Forward", "arrow-right", h_forward))
        // ── Spacer ───────────────────────────────────────────────────────────
        .child(div().flex_1())
        // ── Right-side tools ─────────────────────────────────────────────────
        .child(toolbar_btn("Find", "search", h_find))
        .child(toolbar_btn("Settings", "settings", h_settings))
}

#[doc(hidden)]
pub fn ensure_used_toolbar() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let _b1 = toolbar_button("lbl", "search", "tip");
    let _b2 = toolbar_button_wide("lbl", "search");
}
