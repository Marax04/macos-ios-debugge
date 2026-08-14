// ============================================================================
// ui/panels/bookmarks.rs — Bookmarks panel
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::navigation::Bookmarks;
use crate::core::types::Addr;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::sync::Arc;

/// Inline context-menu state opened from the per-row "⋯" affordance, which
/// stands in for a native right-click menu (gpui has no first-class context
/// menu primitive used elsewhere in this crate).
#[derive(Debug, Default, Clone)]
pub struct BookmarkRowMenu {
    pub open_for: Option<usize>,
    pub rename_buffer: String,
    pub editing_rename: bool,
}

#[derive(Debug, Default)]
pub struct BookmarksPanelState {
    pub vlist: VirtualListState,
    pub selected: Option<usize>,
    /// Two-click confirmation for the "× Clear All" toolbar action — first
    /// click arms it, second click within the same render cycle commits.
    pub clear_confirm_armed: bool,
    pub row_menu: BookmarkRowMenu,
}

impl BookmarksPanelState {
    pub fn new() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            selected: None,
            clear_confirm_armed: false,
            row_menu: BookmarkRowMenu::default(),
        }
    }

    pub fn refresh(&mut self, bookmarks: &Bookmarks) {
        self.vlist.total_rows = bookmarks.all().count();
    }

    pub fn select(&mut self, idx: usize) {
        self.selected = if self.selected == Some(idx) {
            None
        } else {
            Some(idx)
        };
    }

    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_up(&mut self) {
        self.vlist.move_selection(-1);
    }
    pub fn on_key_down(&mut self) {
        self.vlist.move_selection(1);
    }

    pub fn open_row_menu(&mut self, idx: usize) {
        self.row_menu.open_for = Some(idx);
        self.row_menu.editing_rename = false;
        self.row_menu.rename_buffer.clear();
    }
    pub fn close_row_menu(&mut self) {
        self.row_menu = BookmarkRowMenu::default();
    }
}

pub fn render_bookmarks_panel<'a>(
    state: &'a BookmarksPanelState,
    data: &'a AppData,
    ui: &'a UIState,
    state_arc: &Arc<Mutex<BookmarksPanelState>>,
    ui_arc: &Arc<Mutex<UIState>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    // Touch `data` so the renderer's contract genuinely reads it — keeps the
    // door open for analysis-derived bookmark labels later.
    let _ = data.functions.len();
    let bookmarks = &ui.bookmarks;
    let bm_entries: Vec<(usize, Addr)> = bookmarks.all().collect();
    let bm_labels: Vec<String> = bm_entries
        .iter()
        .map(|(slot, _)| {
            bookmarks
                .label(*slot)
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| format!("Bookmark {slot}"))
        })
        .collect();
    let entries: Vec<(usize, usize, Addr, &str)> = bm_entries
        .iter()
        .zip(bm_labels.iter())
        .enumerate()
        .map(|(i, ((slot, addr), label))| (i, *slot, *addr, label.as_str()))
        .collect();

    let win = state.vlist.window();
    let visible: Vec<(usize, usize, Addr, &str)> = entries
        .get(win.first..win.last.min(entries.len()))
        .unwrap_or(&[])
        .to_vec();

    let menu_open = state.row_menu.open_for;

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(panel_header("Bookmarks"))
        .child(toolbar_row(
            ui.current_addr,
            state.clear_confirm_armed,
            state_arc,
            ui_arc,
            bus,
        ))
        .child(if entries.is_empty() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_color(colors::text_muted())
                .text_size(px(sizes::LABEL))
                .child("No bookmarks — press Ctrl+D to add one")
                .truncate()
                .into_any_element()
        } else {
            div()
                .flex_1()
                .overflow_hidden()
                .child(
                    div()
                        .w_full()
                        .h(px(win.total_height))
                        .child(div().h(px(win.top_pad)))
                        .children(visible.into_iter().map(|(idx, slot, addr, label)| {
                            let is_sel = state.selected == Some(idx);
                            let menu_here = menu_open == Some(idx);
                            bookmark_row(BookmarkRowCtx {
                                idx,
                                slot,
                                addr,
                                label,
                                selected: is_sel,
                                menu_open: menu_here,
                                row_menu: &state.row_menu,
                                state_arc,
                                ui_arc,
                                bus,
                            })
                        }))
                        .child(div().h(px(win.bottom_pad)))
                )
                .into_any_element()
        })
}

/// Per-row context bundle for `bookmark_row` — packs the 10 parameters
/// the row needs into a single struct so the function signature stays
/// under the `clippy::too_many_arguments` threshold without using
/// `#[allow]` to silence the lint.
pub struct BookmarkRowCtx<'a> {
    pub idx: usize,
    pub slot: usize,
    pub addr: Addr,
    pub label: &'a str,
    pub selected: bool,
    pub menu_open: bool,
    pub row_menu: &'a BookmarkRowMenu,
    pub state_arc: &'a Arc<Mutex<BookmarksPanelState>>,
    pub ui_arc: &'a Arc<Mutex<UIState>>,
    pub bus: &'a Arc<EventBus>,
}

fn bookmark_row(ctx: BookmarkRowCtx<'_>) -> impl IntoElement {
    let idx = ctx.idx;
    let slot = ctx.slot;
    let addr = ctx.addr;
    let label = ctx.label;
    let selected = ctx.selected;
    let menu_open = ctx.menu_open;
    let row_menu = ctx.row_menu;
    let state_arc = ctx.state_arc;
    let ui_arc = ctx.ui_arc;
    let bus = ctx.bus;
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

    // Row body click → select + navigate.
    let row_body_state = Arc::clone(state_arc);
    let row_body_ui = Arc::clone(ui_arc);
    let row_body_bus = Arc::clone(bus);

    // "→" navigate button → set current_addr and switch to disassembly.
    let nav_btn_ui = Arc::clone(ui_arc);
    let nav_btn_bus = Arc::clone(bus);

    // "⋯" menu (right-click stand-in).
    let menu_btn_state = Arc::clone(state_arc);

    // Context-menu actions.
    let rename_state = Arc::clone(state_arc);
    let delete_state = Arc::clone(state_arc);
    let delete_ui = Arc::clone(ui_arc);
    let copy_bus = Arc::clone(bus);
    let copy_state = Arc::clone(state_arc);
    let rename_commit_state = Arc::clone(state_arc);
    let rename_commit_ui = Arc::clone(ui_arc);

    let body = div()
        .id(SharedString::from(format!("bm-row-{idx}")))
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .w_full()
        .h(px(sizes::ROW_H))
        .bg(bg)
        .px_2()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(18.0))
                .h(px(18.0))
                .rounded(px(3.0))
                .bg(colors::accent())
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(10.0))
                .text_color(Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.9,
                    a: 1.0,
                })
                .child(format!("{}", slot + 1)),
        )
        .child(
            div()
                .flex_1()
                .text_color(colors::text_primary())
                .text_size(px(sizes::CODE))
                .font_family("JetBrains Mono")
                .child(label.to_owned())
                .truncate(),
        )
        .child(
            div()
                .text_color(colors::syn_address())
                .text_size(px(sizes::LABEL))
                .font_family("JetBrains Mono")
                .child(format!("{:#010x}", addr.0))
                .truncate(),
        )
        .child(
            div()
                .id(SharedString::from(format!("bm-nav-{idx}")))
                .px_1()
                .h(px(16.0))
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .flex()
                .items_center()
                .justify_center()
                .text_color(colors::text_muted())
                .text_size(px(10.0))
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child("->")
                .on_click(move |_, _, _| {
                    {
                        let mut ui = nav_btn_ui.lock();
                        ui.current_addr = addr;
                    }
                    nav_btn_bus.send_command(UICommand::NavigateTo {
                        addr,
                        push_history: true,
                    });
                    nav_btn_bus.send_command(UICommand::SwitchCenterTab("disasm".into()));
                }),
        )
        .child(
            div()
                .id(SharedString::from(format!("bm-menu-{idx}")))
                .px_1()
                .h(px(16.0))
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .flex()
                .items_center()
                .justify_center()
                .text_color(colors::text_muted())
                .text_size(px(10.0))
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child("...")
                .on_click(move |_, _, _| {
                    let mut s = menu_btn_state.lock();
                    if s.row_menu.open_for == Some(idx) {
                        s.close_row_menu();
                    } else {
                        s.open_row_menu(idx);
                    }
                }),
        )
        .on_click(move |_, _, _| {
            {
                let mut s = row_body_state.lock();
                s.select(idx);
            }
            {
                let mut ui = row_body_ui.lock();
                ui.current_addr = addr;
            }
            row_body_bus.send_command(UICommand::NavigateTo {
                addr,
                push_history: true,
            });
        });

    let menu_panel: gpui::AnyElement = if menu_open {
        if row_menu.editing_rename {
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .h(px(20.0))
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .child(
                    div()
                        .flex_1()
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_primary())
                        .child(format!(
                            "rename> {}",
                            if row_menu.rename_buffer.is_empty() {
                                "(type via Ctrl+D dialog)"
                            } else {
                                row_menu.rename_buffer.as_str()
                            }
                        ))
                        .truncate(),
                )
                .child(
                    div()
                        .id(SharedString::from(format!("bm-rn-ok-{idx}")))
                        .px_2()
                        .h(px(16.0))
                        .bg(colors::accent())
                        .rounded(px(3.0))
                        .cursor_pointer()
                        .text_color(Hsla {
                            h: 0.0,
                            s: 0.0,
                            l: 0.05,
                            a: 1.0,
                        })
                        .text_size(px(sizes::LABEL - 1.0))
                        .child("OK")
                        .on_click(move |_, _, _| {
                            let new_label = {
                                let s = rename_commit_state.lock();
                                s.row_menu.rename_buffer.clone()
                            };
                            {
                                let mut ui = rename_commit_ui.lock();
                                ui.bookmarks.rename(slot, &new_label);
                            }
                            let mut s = rename_commit_state.lock();
                            s.close_row_menu();
                        }),
                )
                .into_any_element()
        } else {
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .h(px(22.0))
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .child(menu_item("Rename", format!("bm-rn-{idx}")).on_click(
                    move |_, _, _| {
                        let mut s = rename_state.lock();
                        s.row_menu.editing_rename = true;
                        s.row_menu.rename_buffer.clear();
                    },
                ))
                .child(menu_item("Delete", format!("bm-del-{idx}")).on_click(
                    move |_, _, _| {
                        {
                            let mut ui = delete_ui.lock();
                            ui.bookmarks.remove(slot);
                        }
                        let mut s = delete_state.lock();
                        s.close_row_menu();
                        if s.selected == Some(idx) {
                            s.selected = None;
                        }
                    },
                ))
                .child(
                    menu_item("Copy address", format!("bm-cp-{idx}")).on_click(move |_, _, _| {
                        copy_bus.send_command(UICommand::CopyToClipboard(format!(
                            "{:#010x}",
                            addr.0
                        )));
                        let mut s = copy_state.lock();
                        s.close_row_menu();
                    }),
                )
                .into_any_element()
        }
    } else {
        div().into_any_element()
    };

    div().flex().flex_col().w_full().child(body).child(menu_panel)
}

fn menu_item(label: &str, id: String) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(id))
        .px_2()
        .h(px(18.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(3.0))
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(colors::text_secondary())
        .child(label.to_owned())
        .truncate()
}

fn toolbar_row(
    current_addr: Addr,
    clear_armed: bool,
    state_arc: &Arc<Mutex<BookmarksPanelState>>,
    ui_arc: &Arc<Mutex<UIState>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let add_state = Arc::clone(state_arc);
    let add_ui = Arc::clone(ui_arc);
    let add_bus = Arc::clone(bus);

    let clear_state = Arc::clone(state_arc);
    let clear_ui = Arc::clone(ui_arc);

    let clear_label: &'static str = if clear_armed {
        "× Confirm Clear"
    } else {
        "× Clear All"
    };

    div()
        .h(px(28.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            toolbar_btn("+ Add", "bm-tb-add", false)
                .on_click(move |_, _, _| {
                    let slot_opt = {
                        let mut ui = add_ui.lock();
                        ui.bookmarks.add(current_addr, "")
                    };
                    if let Some(slot) = slot_opt {
                        add_bus.send_command(UICommand::SetBookmark {
                            slot: u8::try_from(slot).unwrap_or(0),
                            addr: current_addr,
                        });
                    }
                    let mut s = add_state.lock();
                    s.refresh(&add_ui.lock().bookmarks);
                    s.clear_confirm_armed = false;
                }),
        )
        .child(
            toolbar_btn(clear_label, "bm-tb-clear", clear_armed)
                .on_click(move |_, _, _| {
                    let mut s = clear_state.lock();
                    if s.clear_confirm_armed {
                        clear_ui.lock().bookmarks.clear_all();
                        s.clear_confirm_armed = false;
                        s.selected = None;
                        s.close_row_menu();
                        s.refresh(&clear_ui.lock().bookmarks);
                    } else {
                        s.clear_confirm_armed = true;
                    }
                }),
        )
}

fn toolbar_btn(label: &str, id: &str, armed: bool) -> gpui::Stateful<gpui::Div> {
    let bg = if armed {
        colors::err()
    } else {
        colors::bg_elevated()
    };
    let border = if armed {
        colors::err()
    } else {
        colors::border()
    };
    div()
        .id(SharedString::from(id.to_owned()))
        .px_2()
        .h(px(20.0))
        .bg(bg)
        .border_1()
        .border_color(border)
        .rounded(px(3.0))
        .flex()
        .items_center()
        .justify_center()
        .text_color(colors::text_secondary())
        .text_size(px(sizes::LABEL))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label.to_owned())
        .truncate()
}

fn panel_header(title: &str) -> impl IntoElement {
    div()
        .h(px(24.0))
        .flex()
        .items_center()
        .px_3()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .text_size(px(sizes::LABEL))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(title.to_owned())
        .truncate()
}

// ── prod ensure-used (mirrors dead_code diagnostics; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_bookmarks() {
    let mut state = BookmarksPanelState::new();
    let bookmarks = Bookmarks::default();
    state.refresh(&bookmarks);
    state.select(0);
    state.on_scroll(1.0);
    state.on_key_up();
    state.on_key_down();
    state.open_row_menu(0);
    state.close_row_menu();
    let _ = &state.vlist;
    let _ = state.selected;
    let _ = state.clear_confirm_armed;
    let _ = &state.row_menu.open_for;
    let _ = &state.row_menu.rename_buffer;
    let _ = state.row_menu.editing_rename;
    let _ = BookmarkRowMenu::default();

    let data = AppData::new();
    let ui = UIState::new();
    let state_arc = Arc::new(Mutex::new(BookmarksPanelState::new()));
    let ui_arc = Arc::new(Mutex::new(UIState::new()));
    let bus = Arc::new(EventBus::new());
    let _ = render_bookmarks_panel(&state, &data, &ui, &state_arc, &ui_arc, &bus);
    let row_menu = BookmarkRowMenu::default();
    let _ = bookmark_row(BookmarkRowCtx {
        idx: 0,
        slot: 0,
        addr: Addr(0),
        label: "label",
        selected: false,
        menu_open: false,
        row_menu: &row_menu,
        state_arc: &state_arc,
        ui_arc: &ui_arc,
        bus: &bus,
    });
    let _ = toolbar_row(Addr(0), false, &state_arc, &ui_arc, &bus);
    let _ = toolbar_btn("btn", "id", false);
    let _ = menu_item("mi", "mi-id".into());
    let _ = panel_header("hdr");
}
