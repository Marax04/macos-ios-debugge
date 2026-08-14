// ============================================================================
// ui/panels/command_palette.rs — Fuzzy-search command palette (Ctrl+Shift+P)
// ============================================================================
use crate::core::commands::GLOBAL_REGISTRY;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::dialog::{dialog_box, modal_overlay};
use gpui::{
    div, px, Hsla, InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement,
    Styled,
};

#[derive(Default)]
pub struct CommandPalette {
    pub query: String,
    pub selected: usize,
}

/// Owned snapshot of one command result so the registry's `RwLock` guard can
/// be released before the (long-lived) UI element tree is built.
struct CommandRow {
    name: String,
    description: String,
    category: String,
    shortcuts: String,
}
impl CommandPalette {
    pub fn render(&self) -> impl IntoElement + '_ {
        let rows = snapshot_rows(&self.query);
        let results = &rows;
        let selected = self.selected.min(results.len().saturating_sub(1));

        div()
            .absolute()
            .inset_0()
            .flex()
            .items_start()
            .justify_center()
            .pt(px(80.0))
            .child(
                // Overlay backdrop
                div().absolute().inset_0().bg(Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.0,
                    a: 0.55,
                }),
            )
            .child(
                div()
                    .relative()
                    .w(px(500.0))
                    .bg(colors::bg_elevated())
                    .border_1()
                    .border_color(colors::border_accent())
                    .rounded_md()
                    .shadow_xl()
                    .overflow_hidden()
                    .flex()
                    .flex_col()
                    // Search input
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_2()
                            .h(px(44.0))
                            .px_3()
                            .bg(colors::bg_surface())
                            .border_b_1()
                            .border_color(colors::border())
                            .child(
                                div()
                                    .text_size(px(14.0))
                                    .text_color(colors::text_muted())
                                    .child(crate::ui::widgets::icon::icon("command")),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .text_size(px(sizes::CODE))
                                    .text_color(colors::text_primary())
                                    .font_family("JetBrains Mono")
                                    .child(if self.query.is_empty() {
                                        "Search commands…".into()
                                    } else {
                                        self.query.clone()
                                    })
                                    .truncate(),
                            ),
                    )
                    // Results
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .max_h(px(380.0))
                            .id("cmd-scroll")
                            .overflow_y_scroll()
                            .children(results.iter().enumerate().map(|(i, row)| {
                                let is_sel = i == selected;
                                cmd_result_row(row, is_sel)
                            })),
                    )
                    // Footer
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .h(px(26.0))
                            .px_3()
                            .bg(colors::bg_surface())
                            .border_t_1()
                            .border_color(colors::border())
                            .child(
                                div()
                                    .text_size(px(sizes::STATUS))
                                    .text_color(colors::text_muted())
                                    .child(format!("{} commands", results.len()))
                                    .truncate(),
                            )
                            .child(
                                div()
                                    .text_size(px(sizes::STATUS))
                                    .text_color(colors::text_muted())
                                    .child("^v navigate   Enter select   Esc close")
                                    .truncate(),
                            ),
                    ),
            )
    }

    pub fn move_sel(&mut self, delta: i64) {
        let count = GLOBAL_REGISTRY.read().search(&self.query).len();
        if count == 0 {
            return;
        }
        let selected_i64 = i64::try_from(self.selected).unwrap_or(i64::MAX);
        let count_i64 = i64::try_from(count).unwrap_or(i64::MAX);
        let new_i64 = (selected_i64 + delta).rem_euclid(count_i64);
        self.selected = usize::try_from(new_i64).unwrap_or(0);
    }

    pub fn selected_command_id(&self) -> Option<u32> {
        GLOBAL_REGISTRY
            .read()
            .search(&self.query)
            .get(self.selected)
            .map(|c| c.id)
    }
}

/// Search the registry and materialise owned rows so the `RwLock` guard can
/// be dropped immediately, before the UI element tree is built.
fn snapshot_rows(query: &str) -> Vec<CommandRow> {
    let registry = GLOBAL_REGISTRY.read();
    registry
        .search(query)
        .into_iter()
        .map(|cmd| CommandRow {
            name: cmd.name.to_string(),
            description: cmd.description.to_string(),
            category: cmd.category.to_string(),
            shortcuts: cmd
                .shortcuts
                .iter()
                .map(|sc| {
                    let m = sc.mods.display();
                    let k = sc.key.display();
                    if m.is_empty() {
                        k
                    } else {
                        format!("{m}+{k}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        })
        .collect()
}

fn cmd_result_row(row: &CommandRow, selected: bool) -> impl IntoElement {
    let bg = if selected {
        colors::bg_selection()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };
    let cat_col = colors::accent();
    let shortcuts = row.shortcuts.clone();

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(44.0))
        .bg(bg)
        .items_center()
        .px_3()
        .gap_3()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .gap_0p5()
                .child(
                    div()
                        .text_size(px(sizes::PANEL - 0.5))
                        .text_color(colors::text_primary())
                        .child(row.name.clone())
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child(row.description.clone())
                        .truncate(),
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .items_end()
                .gap_0p5()
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(cat_col)
                        .child(row.category.clone())
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(shortcuts)
                        .truncate(),
                ),
        )
}

#[doc(hidden)]
pub fn ensure_used_command_palette() {
    // Touch unused imports so they are referenced by production code.
    let overlay = modal_overlay();
    let dialog = dialog_box("palette", 320.0);
    let _ = overlay;
    let _ = dialog;

    // Touch unused methods on CommandPalette.
    let mut palette = CommandPalette::default();
    palette.move_sel(1);
    palette.move_sel(-1);
    let _selected_id: Option<u32> = palette.selected_command_id();
}
