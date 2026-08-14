// ============================================================================
// ui/widgets/dialog.rs — Modal dialog helpers (goto, rename, comment, patch)
// ============================================================================
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, Div, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, Styled,
};

/// A centered modal overlay container (returns Div for chaining).
///
/// The overlay swallows scroll-wheel events so that scrolling while a dialog
/// is visible only moves the dialog's own internal scroll areas — it never
/// leaks through to the workspace beneath. This matches the global "open
/// overlay isolates input" rule the rest of the UI follows.
pub fn modal_overlay() -> Div {
    div()
        .absolute()
        .inset_0()
        .bg(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.6,
        })
        .flex()
        .items_center()
        .justify_center()
        // Swallow scroll wheel events at the modal layer so the underlying
        // workspace never scrolls while a dialog is open. `stop_propagation`
        // is the critical bit — an empty handler still lets the event bubble.
        .on_scroll_wheel(|_, _, cx| cx.stop_propagation())
}

/// The inner dialog box.
pub fn dialog_box(title: &str, width: f32) -> impl IntoElement {
    div()
        .w(px(width))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border_accent())
        .rounded_md()
        .shadow_lg()
        .flex()
        .flex_col()
        .overflow_hidden()
        .child(dialog_header(title))
}

fn dialog_header(title: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(32.0))
        .px_3()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::PANEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child(title.to_owned()),
        )
}

/// Static dialog input (shows value or placeholder).
pub fn dialog_input(placeholder: &str, value: &str) -> impl IntoElement {
    dialog_input_focused(placeholder, value, false)
}

/// Dialog input with optional focused cursor indicator.
pub fn dialog_input_focused(placeholder: &str, value: &str, focused: bool) -> impl IntoElement {
    let border_color = if focused {
        colors::accent()
    } else {
        colors::border_focus()
    };
    let (display_text, text_color) = if value.is_empty() {
        (placeholder.to_owned(), colors::text_muted())
    } else {
        (value.to_owned(), colors::text_primary())
    };
    div()
        .w_full()
        .h(px(28.0))
        .bg(colors::bg_base())
        .border_1()
        .border_color(border_color)
        .rounded_sm()
        .px_2()
        .flex()
        .items_center()
        .gap(px(1.0))
        .text_size(px(sizes::CODE))
        .text_color(text_color)
        .font_family("JetBrains Mono")
        .child(display_text)
        .child(if focused {
            div()
                .w(px(1.5))
                .h(px(14.0))
                .bg(colors::accent())
                .flex_shrink_0()
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

pub fn dialog_button(label: &str, primary: bool) -> Div {
    let bg = if primary {
        colors::accent()
    } else {
        colors::bg_surface()
    };
    let fg = if primary {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.05,
            a: 1.0,
        }
    } else {
        colors::text_primary()
    };
    div()
        .h(px(26.0))
        .px_3()
        .bg(bg)
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(sizes::LABEL))
        .text_color(fg)
        .font_weight(if primary {
            FontWeight::SEMIBOLD
        } else {
            FontWeight::NORMAL
        })
        .hover(|s| {
            s.bg(if primary {
                colors::accent_hover()
            } else {
                colors::bg_hover()
            })
        })
        .child(label.to_owned())
}

#[doc(hidden)]
pub fn ensure_used_dialog() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let _b = dialog_box("title", 300.0);
    let _i = dialog_input("placeholder", "value");
}
