// ============================================================================
// ui/panels/log_panel.rs
// ============================================================================
use crate::core::app_state::{LogEntry, LogLevel, UIState};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{div, px, App, ClickEvent, FontWeight, InteractiveElement, IntoElement, MouseButton, MouseDownEvent, ParentElement, StatefulInteractiveElement, Styled, Window};

// Maximum entries rendered in the DOM at once. The list is tail-sliced so we
// always show the most recent entries. 500 simple divs is negligible for GPU.
const MAX_VISIBLE: usize = 500;

pub struct LogPanel {
    /// Kept for compatibility with on_scroll callers (functions panel pattern).
    /// Only used when auto_scroll=false (user has scrolled up manually).
    pub vlist: VirtualListState,
    pub auto_scroll: bool,
    /// Indice (relativo allo slice visibile) della riga di log
    /// selezionata. None = nessuna selezione. Wired al per-row mouse
    /// down; Ctrl+C ne copia il contenuto nel clipboard.
    pub selected_row: Option<usize>,
    /// Range-selection anchor (set on plain click) and cursor (set on
    /// Shift+click or drag). When anchor!=cursor, Ctrl+C copies every
    /// line between them inclusive — He needs multi-line copy from the
    /// Output Log, not just one row at a time.
    pub sel_anchor: Option<usize>,
    pub sel_cursor: Option<usize>,
}

impl Default for LogPanel {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H - 2.0),
            auto_scroll: true,
            selected_row: None,
            sel_anchor: None,
            sel_cursor: None,
        }
    }
}

impl LogPanel {
    /// Called from app.rs whenever log_entries change.
    pub fn update(&mut self, entries: &[LogEntry]) {
        self.vlist.total_rows = entries.len();
        // Only call scroll_to_row when viewport_h is known (> 0) to avoid
        // the top_pad overshoot bug that makes all entries invisible.
        if self.auto_scroll && !entries.is_empty() && self.vlist.viewport_h > 0.0 {
            self.vlist.scroll_to_row(entries.len() - 1);
        }
    }

    pub fn render<'a>(
        &'a self,
        ui: &'a UIState,
        on_toggle_autoscroll: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
        on_clear: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
        on_copy: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
        bus: std::sync::Arc<crate::core::event_bus::EventBus>,
    ) -> impl IntoElement + 'a {
        let entries = &ui.log_entries;
        let start = entries.len().saturating_sub(MAX_VISIBLE);
        let visible = &entries[start..];
        let sel_row = self.selected_row;

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_base())
            .child(log_hdr(self.auto_scroll, on_toggle_autoscroll, on_clear, on_copy))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .id("log-msg-scroll")
                    .overflow_y_scroll()
                    .w_full()
                    .pb_2()
                    .children(visible.iter().enumerate().map(|(i, e)| {
                        let in_range = match (self.sel_anchor, self.sel_cursor) {
                            (Some(a), Some(c)) => {
                                let (lo, hi) = if a <= c { (a, c) } else { (c, a) };
                                i >= lo && i <= hi
                            }
                            _ => false,
                        };
                        log_row_selectable(e, i, sel_row == Some(i) || in_range, bus.clone())
                    })),
            )
    }

    /// Restituisce il testo della riga selezionata (o None se nessuna
    /// selezione). Usato dal Ctrl+C handler globale per copiare la riga
    /// del log corrente in clipboard.
    pub fn selected_text(&self, ui: &UIState) -> Option<String> {
        let entries = &ui.log_entries;
        let start = entries.len().saturating_sub(MAX_VISIBLE);
        let visible = &entries[start..];
        let fmt = |e: &LogEntry| {
            let time = e.time.get(11..19).unwrap_or("").to_owned();
            let lvl = match e.level {
                LogLevel::Info => "INFO",
                LogLevel::Warn => "WARN",
                LogLevel::Error => "ERROR",
                LogLevel::Debug => "DEBUG",
            };
            format!("{time} {lvl} {}", e.msg)
        };
        if let (Some(a), Some(c)) = (self.sel_anchor, self.sel_cursor) {
            let (lo, hi) = if a <= c { (a, c) } else { (c, a) };
            let mut out = Vec::with_capacity(hi - lo + 1);
            for i in lo..=hi {
                if let Some(e) = visible.get(i) {
                    out.push(fmt(e));
                }
            }
            if !out.is_empty() {
                return Some(out.join("\n"));
            }
        }
        let row = self.selected_row?;
        let e = visible.get(row)?;
        Some(fmt(e))
    }

    /// Seleziona la riga di log all'indice `row` (clamp al numero di
    /// righe visibili). Chiamata dal mouse-down per-row.
    pub fn select_row(&mut self, row: usize) {
        self.selected_row = Some(row);
        self.sel_anchor = Some(row);
        self.sel_cursor = Some(row);
    }

    /// Estende la selezione di range mantenendo l'anchor fisso e
    /// spostando il cursor. Usato dal Shift+click per copiare più righe.
    pub fn extend_selection_to(&mut self, row: usize) {
        if self.sel_anchor.is_none() {
            self.sel_anchor = Some(row);
        }
        self.sel_cursor = Some(row);
        self.selected_row = Some(row);
    }

    /// Resetta la selezione.
    pub fn clear_selection(&mut self) {
        self.selected_row = None;
        self.sel_anchor = None;
        self.sel_cursor = None;
    }

    /// Called from app.rs on_scroll_wheel for the bottom panel.
    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
        // If the user scrolled up manually, disable auto-scroll.
        if d < 0.0 {
            self.auto_scroll = false;
        }
    }
}

fn log_row_selectable(
    e: &LogEntry,
    row_idx: usize,
    selected: bool,
    bus: std::sync::Arc<crate::core::event_bus::EventBus>,
) -> impl IntoElement {
    let (icon, col) = match e.level {
        LogLevel::Info => ("(i)", colors::text_secondary()),
        LogLevel::Warn => ("[!]", colors::warn()),
        LogLevel::Error => ("×", colors::err()),
        LogLevel::Debug => ("·", colors::text_muted()),
    };
    use crate::core::event_bus::UICommand;
    let bus_cl = bus.clone();
    div()
        .id(gpui::SharedString::from(format!("log-row-{row_idx}")))
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H - 2.0))
        .items_center()
        .gap_2()
        .px_2()
        .cursor_pointer()
        .bg(if selected {
            colors::bg_selection()
        } else {
            gpui::Hsla { h: 0.0, s: 0.0, l: 0.0, a: 0.0 }
        })
        // Selezione log come nel listing:
        //  - click semplice → singola riga + anchor reset
        //  - Shift+click   → estende il range esistente
        //  - drag (mouse-down poi sposta sopra altre righe col tasto
        //    sinistro premuto) → estende riga per riga finché rilasci
        //
        // gpui::MouseMoveEvent.pressed_button == Some(Left) ci dice se
        // il mouse sta trascinando con click sinistro attivo, quindi
        // possiamo distinguere drag-select da hover normale senza
        // tenere stato globale extra.
        .on_mouse_down(MouseButton::Left, {
            let bus_cl = bus_cl.clone();
            move |ev: &MouseDownEvent, _, _| {
                if ev.modifiers.shift {
                    bus_cl.send_command(UICommand::LogExtendSelectionToRow(row_idx));
                } else {
                    bus_cl.send_command(UICommand::LogSelectRow(row_idx));
                }
            }
        })
        .on_mouse_move(move |ev: &gpui::MouseMoveEvent, _, _| {
            if ev.pressed_button == Some(MouseButton::Left) {
                bus_cl.send_command(UICommand::LogExtendSelectionToRow(row_idx));
            }
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(col)
                .w(px(14.0))
                .child(icon),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .w(px(70.0))
                .truncate()
                .child(e.time.get(11..19).unwrap_or("").to_owned()),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(col)
                .truncate()
                .child(e.msg.clone()),
        )
}

fn log_hdr(
    auto_scroll: bool,
    on_toggle: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_clear: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_copy: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    use crate::ui::widgets::icon::icon_sized;
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::PANEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Output Log"),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                // ── Copy-selection button ────────────────────────────
                // Bypassa la dipendenza dal Ctrl+C / focus: cliccando
                // questo bottone si copia in clipboard la riga (o il
                // range Shift+click) attualmente selezionato. Se nulla
                // è selezionato, copia l'intero log visibile.
                .child(
                    div()
                        .id("log-copy-btn")
                        .on_click(on_copy)
                        .px_2()
                        .py_px()
                        .cursor_pointer()
                        .bg(colors::bg_elevated())
                        .border_1()
                        .border_color(colors::border())
                        .rounded(px(3.0))
                        .hover(|s| s.bg(colors::bg_hover()))
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child("Copy"),
                )
                // ── Broom (Clear) button ─────────────────────────────
                .child(
                    div()
                        .id("log-clear-btn")
                        .on_click(on_clear)
                        .px_2()
                        .py_px()
                        .cursor_pointer()
                        .bg(colors::bg_elevated())
                        .border_1()
                        .border_color(colors::border())
                        .rounded(px(3.0))
                        .hover(|s| s.bg(colors::bg_hover()))
                        .text_color(colors::text_muted())
                        .child(icon_sized("broom", 14.0, 14.0)),
                )
                // ── Auto-scroll toggle (esistente) ───────────────────
                .child(
                    div()
                        .id("log-autoscroll-btn")
                        .on_click(on_toggle)
                        .px_2()
                        .py_px()
                        .cursor_pointer()
                        .bg(if auto_scroll {
                            colors::accent().opacity(0.15)
                        } else {
                            colors::bg_elevated()
                        })
                        .border_1()
                        .border_color(if auto_scroll {
                            colors::accent()
                        } else {
                            colors::border()
                        })
                        .rounded(px(3.0))
                        .hover(|s| s.bg(colors::bg_hover()))
                        .text_size(px(sizes::LABEL))
                        .text_color(if auto_scroll {
                            colors::accent()
                        } else {
                            colors::text_muted()
                        })
                        .truncate()
                        .child(if auto_scroll {
                            "Auto-scroll ●"
                        } else {
                            "Auto-scroll ○"
                        }),
                ),
        )
}

pub fn ensure_used_log_panel() {
    let mut p = LogPanel::default();
    p.on_scroll(1.0);
    let _ = p.auto_scroll;
}
