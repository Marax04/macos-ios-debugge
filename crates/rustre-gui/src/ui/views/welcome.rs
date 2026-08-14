// ============================================================================
// ui/views/welcome.rs — Welcome / splash screen shown when no file is open
// ============================================================================

use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::toolbar::{icon, icon_color};
use gpui::{
    div, px, svg, App, ClickEvent, FontWeight, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled, Window,
};

/// Closure type for welcome-tile clicks. Created in `IDAApp::render_inner`
/// via `cx.listener(...)` and wired into the four action tiles below.
pub type WelcomeClickHandler = Box<dyn Fn(&ClickEvent, &mut Window, &mut App) + 'static>;

/// Click handlers for the four big tiles on the welcome screen.
///
/// Field names intentionally drop the redundant `on_` prefix to keep the
/// struct narrow (per `clippy::struct_field_names`) — the type name already
/// makes their role unambiguous.
pub struct WelcomeHandlers {
    pub open_binary: WelcomeClickHandler,
    pub open_project: WelcomeClickHandler,
    pub settings: WelcomeClickHandler,
    pub commands: WelcomeClickHandler,
}

pub fn render_welcome(handlers: WelcomeHandlers) -> impl IntoElement {
    div()
        .id("welcome-scroll")
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_base())
        .items_center()
        .justify_center()
        .overflow_y_scroll()
        .child(
            // Centred content column with a max-width cap so the layout stays
            // pleasant on ultra-wide monitors AND wraps on tiny ones.
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap_8()
                .max_w(px(960.0))
                .w_full()
                .px_6()
                .py_8()
                // ── Logo / title block ───────────────────────────────────
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .items_center()
                        .gap_3()
                        .child(
                            // Zyphora logo (SVG in assets/branding/).
                            svg()
                                .path(SharedString::from("branding/zyphora_logo.svg"))
                                .w(px(96.0))
                                .h(px(96.0))
                                .flex_none(),
                        )
                        .child(
                            div()
                                .text_size(px(36.0))
                                .font_weight(FontWeight::BOLD)
                                .text_color(colors::accent())
                                .child("Zyphora"),
                        )
                        .child(
                            div()
                                .text_size(px(sizes::PANEL + 2.0))
                                .text_color(colors::text_secondary())
                                .child("Reversing Workstation"),
                        )
                        .child(
                            div()
                                .text_size(px(sizes::LABEL))
                                .text_color(colors::text_muted())
                                .child("Powered by GPUI  -  Capstone  -  Rust"),
                        ),
                )
                // ── Quick action tiles (flex-wrap on narrow screens) ─────
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .flex_wrap()
                        .gap_4()
                        .justify_center()
                        .w_full()
                        .child(action_tile(
                            "welcome-open-binary",
                            "Open Binary",
                            "folder-open",
                            "Ctrl+O",
                            "Load a PE/ELF/Mach-O for analysis",
                            handlers.open_binary,
                        ))
                        .child(action_tile(
                            "welcome-open-project",
                            "Open Project",
                            "file-code",
                            "Ctrl+Shift+O",
                            "Restore a saved Zyphora project",
                            handlers.open_project,
                        ))
                        .child(action_tile(
                            "welcome-settings",
                            "Settings",
                            "settings",
                            "-",
                            "Configure theme, fonts, analysis",
                            handlers.settings,
                        ))
                        .child(action_tile(
                            "welcome-commands",
                            "Commands",
                            "search",
                            "Ctrl+Shift+P",
                            "Browse all available commands",
                            handlers.commands,
                        )),
                )
                // ── Feature bullets ───────────────────────────────────────
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .items_start()
                        .child(feature_row(
                            "Virtualized listing view  -  millions of lines at 60 fps",
                        ))
                        .child(feature_row("Sugiyama CFG layout with pan/zoom and minimap"))
                        .child(feature_row("Pseudo-C decompiler with source maps"))
                        .child(feature_row(
                            "Hex view with LRU page cache and byte-selection",
                        ))
                        .child(feature_row(
                            "Integrated debugger  -  breakpoints, step, registers",
                        ))
                        .child(feature_row("Fuzzy command palette  -  press Ctrl+Shift+P")),
                )
                // ── Version line ─────────────────────────────────────────
                .child(
                    div()
                        .text_size(px(sizes::STATUS))
                        .text_color(colors::text_muted())
                        .child(format!(
                            "v{}  -  2026 Zyphora Reversing Dev Team",
                            env!("CARGO_PKG_VERSION")
                        )),
                ),
        )
}

fn action_tile(
    id: &'static str,
    title: &str,
    icon_name: &str,
    shortcut: &str,
    desc: &str,
    on_click: WelcomeClickHandler,
) -> impl IntoElement {
    // Width clamp: shrinks down to 180 on narrow screens but never blows past
    // 240. Combined with `.flex_wrap()` on the parent this produces a 4-up
    // grid on wide monitors, 2-up around 700 px, 1-up on phones-portrait.
    div()
        .id(SharedString::from(id))
        .flex()
        .flex_col()
        .gap_1()
        .min_w(px(180.0))
        .max_w(px(240.0))
        .flex_1()
        .p_4()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_md()
        .cursor_pointer()
        .hover(|s| {
            s.border_color(colors::border_accent())
                .bg(colors::bg_hover())
        })
        .on_click(on_click)
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(icon(icon_name, 14.0))
                        .child(
                            div()
                                .text_size(px(sizes::PANEL))
                                .text_color(colors::text_primary())
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(title.to_owned()),
                        ),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(shortcut.to_owned()),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(desc.to_owned()),
        )
}

fn feature_row(text: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_2()
        .items_center()
        .child(icon_color("check", 12.0, colors::ok()))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(text.to_owned()),
        )
}
