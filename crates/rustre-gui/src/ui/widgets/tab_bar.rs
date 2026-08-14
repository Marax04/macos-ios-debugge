// ============================================================================
// ui/widgets/tab_bar.rs — Tab bar with SVG icons and click handlers
// Icons: Lucide (MIT) embedded via assets/
// ============================================================================

use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::toolbar::icon_color;
use gpui::{
    div, px, App, ClickEvent, ElementId, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled, Window,
};

type TabClickHandler = Box<dyn Fn(&ClickEvent, &mut Window, &mut App) + 'static>;

pub struct Tab {
    pub id: &'static str,
    pub label: &'static str,
    /// Lucide icon name (without .svg), e.g. "function-square"
    pub icon: &'static str,
}

/// Render a tab bar.
///
/// `panel_id`  – unique panel identifier used to build stable element IDs.
/// `handlers`  – optional per-tab click callbacks (must match `tabs` length if provided).
///               Created with `cx.listener(...)` in the parent view's render method.
pub fn render_tab_bar(
    tabs: &[Tab],
    active: &str,
    panel_id: &'static str,
    handlers: Vec<TabClickHandler>,
) -> impl IntoElement {
    div()
        .id(ElementId::Name(SharedString::from(format!(
            "{panel_id}-tabs-bar"
        ))))
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::TAB_H))
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        // Allow horizontal scrolling so panel-tabs are always reachable on
        // narrow viewports (e.g. when the right panel shrinks and labels like
        // "Bookmarks" would otherwise be clipped).
        .overflow_x_scroll()
        .children(tabs.iter().zip(handlers).map(|(tab, handler)| {
            let is_active = tab.id == active;
            let bg = if is_active {
                colors::bg_elevated()
            } else {
                colors::bg_surface()
            };
            let text_col = if is_active {
                colors::text_bright()
            } else {
                colors::text_muted()
            };
            let border_b_col = if is_active {
                colors::accent()
            } else {
                Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.0,
                    a: 0.0,
                }
            };
            let icon_name = tab.icon;
            let elem_id = ElementId::Name(SharedString::from(format!("{panel_id}-tab-{}", tab.id)));

            div()
                .id(elem_id)
                .flex()
                .flex_row()
                .items_center()
                .gap(px(4.0))
                .px_2()
                .h_full()
                // Responsive: every tab is allowed to shrink down to its icon,
                // but never below `min_w` so the icon stays visible. The label
                // gets truncated with an ellipsis instead of pushing siblings.
                .min_w(px(34.0))
                .flex_shrink(1.0)
                .bg(bg)
                .border_b_2()
                .border_color(border_b_col)
                .cursor_pointer()
                .hover(|s| {
                    if is_active {
                        s
                    } else {
                        s.bg(colors::bg_hover())
                    }
                })
                .on_click(handler)
                .child(icon_color(icon_name, 12.0, text_col))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_size(px(sizes::LABEL))
                        .text_color(text_col)
                        .whitespace_nowrap()
                        .overflow_hidden()
                        .text_ellipsis()
                        .child(tab.label),
                )
        }))
}
