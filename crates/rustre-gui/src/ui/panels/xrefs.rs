// ============================================================================
// ui/panels/xrefs.rs — Cross-references panel with navigation
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Addr, XrefEntry, XrefKind};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

/// Column to sort the xref list by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XrefSortCol {
    Kind,
    #[default]
    Addr,
    Symbol,
    Label,
}

/// Group cross-references by kind for the statistics bar.
#[derive(Default, Clone)]
pub struct XrefStats {
    pub calls: usize,
    pub jumps: usize,
    pub data_refs: usize,
    pub reads: usize,
    pub writes: usize,
    pub fallthroughs: usize,
}

impl XrefStats {
    pub fn compute(rows: &[XrefEntry]) -> Self {
        let mut s = Self::default();
        for x in rows {
            match x.kind {
                XrefKind::Call => s.calls += 1,
                XrefKind::Jump => s.jumps += 1,
                XrefKind::DataRef => s.data_refs += 1,
                XrefKind::DataRead => s.reads += 1,
                XrefKind::DataWrite => s.writes += 1,
                XrefKind::Fallthrough => s.fallthroughs += 1,
            }
        }
        s
    }
}

/// Display mode for the xrefs panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XrefDisplay {
    #[default]
    To, // xrefs TO the current addr (callers, data readers, etc.)
    From, // xrefs FROM the current addr (callees, jumps, etc.)
    All,  // show both directions
}

impl XrefDisplay {
    pub const fn label(self) -> &'static str {
        match self {
            Self::To => "To",
            Self::From => "From",
            Self::All => "All",
        }
    }
}

pub struct XrefsPanel {
    pub vlist: VirtualListState,
    pub target_addr: Addr,
    pub show_to: bool, // true=xrefs TO current addr, false=FROM
    pub display: XrefDisplay,
    pub filter: String,
    pub kind_filter: Option<XrefKind>,
    pub sort_col: XrefSortCol,
    pub sort_asc: bool,
    /// Pending sort column written by header on_click handlers; consumed by `refresh`.
    pending_sort: Arc<(AtomicU8, AtomicBool)>,
    rows: Vec<XrefEntry>,
    stats: XrefStats,
    cached_rev: u64,
    cached_addr: u64,
}

impl Default for XrefsPanel {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            target_addr: Addr::INVALID,
            show_to: true,
            display: XrefDisplay::To,
            filter: String::new(),
            kind_filter: None,
            sort_col: XrefSortCol::default(),
            sort_asc: true,
            pending_sort: Arc::new((AtomicU8::new(u8::MAX), AtomicBool::new(false))),
            rows: Vec::new(),
            stats: XrefStats::default(),
            cached_rev: 0,
            cached_addr: u64::MAX,
        }
    }
}

impl XrefsPanel {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        // Consume any pending sort change from header on_click handlers.
        if self.pending_sort.1.swap(false, Ordering::AcqRel) {
            let raw = self.pending_sort.0.load(Ordering::Acquire);
            let col = match raw {
                0 => XrefSortCol::Kind,
                1 => XrefSortCol::Addr,
                2 => XrefSortCol::Symbol,
                3 => XrefSortCol::Label,
                _ => self.sort_col,
            };
            if self.sort_col == col {
                self.sort_asc = !self.sort_asc;
            } else {
                self.sort_col = col;
                self.sort_asc = true;
            }
            self.cached_addr = u64::MAX;
        }
        if self.cached_rev == rev && self.cached_addr == self.target_addr.0 {
            return;
        }
        self.cached_rev = rev;
        self.cached_addr = self.target_addr.0;

        self.rows = match self.display {
            XrefDisplay::To => data
                .xrefs_to
                .get(&self.target_addr.0)
                .cloned()
                .unwrap_or_default(),
            XrefDisplay::From => data
                .xrefs_from
                .get(&self.target_addr.0)
                .cloned()
                .unwrap_or_default(),
            XrefDisplay::All => {
                let mut all = data
                    .xrefs_to
                    .get(&self.target_addr.0)
                    .cloned()
                    .unwrap_or_default();
                all.extend(
                    data.xrefs_from
                        .get(&self.target_addr.0)
                        .cloned()
                        .unwrap_or_default(),
                );
                all
            }
        };

        // Apply kind filter
        if let Some(k) = self.kind_filter {
            self.rows.retain(|x| x.kind == k);
        }

        // Apply text filter
        let q = self.filter.to_lowercase();
        if !q.is_empty() {
            self.rows.retain(|x| {
                format!("{:#x}", x.from.0).contains(&q)
                    || format!("{:#x}", x.to.0).contains(&q)
                    || x.label.as_deref().unwrap_or("").to_lowercase().contains(&q)
            });
        }

        // Apply sort
        let show_to = self.show_to;
        let asc = self.sort_asc;
        match self.sort_col {
            XrefSortCol::Kind => {
                self.rows
                    .sort_by(|a, b| (a.kind as u8).cmp(&(b.kind as u8)));
            }
            XrefSortCol::Addr => {
                self.rows.sort_by(|a, b| {
                    let av = if show_to { a.from.0 } else { a.to.0 };
                    let bv = if show_to { b.from.0 } else { b.to.0 };
                    av.cmp(&bv)
                });
            }
            XrefSortCol::Symbol => {
                self.rows.sort_by(|a, b| {
                    let av = if show_to { a.from.0 } else { a.to.0 };
                    let bv = if show_to { b.from.0 } else { b.to.0 };
                    av.cmp(&bv)
                });
            }
            XrefSortCol::Label => {
                self.rows.sort_by(|a, b| {
                    a.label
                        .as_deref()
                        .unwrap_or("")
                        .cmp(b.label.as_deref().unwrap_or(""))
                });
            }
        }
        if !asc {
            self.rows.reverse();
        }

        self.stats = XrefStats::compute(&self.rows);
        self.vlist.total_rows = self.rows.len();
    }

    /// Force the next call to [`refresh`] to rebuild even if rev/addr unchanged.
    pub const fn invalidate_cache(&mut self) {
        self.cached_addr = u64::MAX;
    }

    /// Toggle sort direction if same column, otherwise switch column with ascending.
    pub fn set_sort(&mut self, col: XrefSortCol) {
        if self.sort_col == col {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = col;
            self.sort_asc = true;
        }
        self.invalidate_cache();
    }

    pub fn set_target(&mut self, addr: Addr) {
        if self.target_addr != addr {
            self.target_addr = addr;
            self.cached_addr = u64::MAX; // force rebuild
        }
    }

    pub const fn toggle_direction(&mut self) {
        self.show_to = !self.show_to;
        self.display = if self.show_to {
            XrefDisplay::To
        } else {
            XrefDisplay::From
        };
        self.cached_addr = u64::MAX;
    }

    pub fn render<'a>(
        &'a self,
        data: &'a AppData,
        ui_arc: &Arc<Mutex<UIState>>,
        bus: &Arc<EventBus>,
    ) -> impl IntoElement + 'a {
        let win = self.vlist.window();

        let hdr_label = if self.target_addr.is_valid() {
            format!(
                "Xrefs ({}) — {:#010x}",
                self.display.label(),
                self.target_addr.0
            )
        } else {
            "Cross-References".to_string()
        };

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_panel())
            .child(xref_header(&hdr_label, self.rows.len()))
            .child(direction_bar(self.show_to, Arc::clone(ui_arc), Arc::clone(bus)))
            .child(filter_bar(&self.filter, Arc::clone(ui_arc)))
            .child(stats_bar(&self.stats))
            .child(col_headers(
                self.show_to,
                self.sort_col,
                self.sort_asc,
                Arc::clone(&self.pending_sort),
            ))
            .child(if self.rows.is_empty() {
                empty_state(self.target_addr.is_valid()).into_any_element()
            } else {
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .flex_1()
                    .overflow_hidden()
                    .child(
                        div()
                            .w_full()
                            .h(px(win.total_height))
                            .child(div().h(px(win.top_pad)))
                            .children(
                                self.rows[win.first..win.last]
                                    .iter()
                                    .enumerate()
                                    .map(|(i, x)| (win.first + i, x))
                                    .map(|(i, x)| {
                                        let sel = self.vlist.selected_row == Some(i);
                                        let func_name = if self.show_to {
                                            data.name_at_addr(x.from).unwrap_or_default()
                                        } else {
                                            data.name_at_addr(x.to).unwrap_or_default()
                                        };
                                        let nav = Arc::clone(ui_arc);
                                        let bus_nav = Arc::clone(bus);
                                        xref_row(x, &func_name, self.show_to, sel, i, nav, bus_nav)
                                    }),
                            )
                            .child(div().h(px(win.bottom_pad)))
                    )
                    .into_any_element()
            })
    }

    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_down(&mut self, d: i64) {
        self.vlist.move_selection(d);
    }

    pub fn selected_addr(&self) -> Option<Addr> {
        let row = self.vlist.selected_row?;
        let x = self.rows.get(row)?;
        if self.show_to {
            Some(x.from)
        } else {
            Some(x.to)
        }
    }
}

// ── Row renderer ──────────────────────────────────────────────────────────────

fn xref_row(
    x: &XrefEntry,
    func_name: &str,
    show_to: bool,
    sel: bool,
    row_idx: usize,
    ui_arc: Arc<Mutex<UIState>>,
    bus: Arc<EventBus>,
) -> impl IntoElement {
    let bg = if sel {
        colors::bg_selection()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };
    let border_color = if sel {
        colors::accent()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };
    let addr = if show_to { x.from } else { x.to };

    let (kind_col, kind_bg) = xref_kind_colors(x.kind);
    let kind_label = x.kind.as_str();

    div()
        .id(SharedString::from(format!("xref-row-{row_idx}")))
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H))
        .bg(bg)
        .items_center()
        .cursor_pointer()
        .border_l(px(2.0))
        .border_color(border_color)
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            {
                let mut ui = ui_arc.lock();
                ui.current_addr = addr;
            }
            bus.send_command(UICommand::NavigateTo {
                addr,
                push_history: true,
            });
            bus.send_command(UICommand::SwitchRightTab("xrefs".to_string()));
        })
        // Kind badge
        .child(
            div().w(px(52.0)).px_1().child(
                div()
                    .px_1()
                    .rounded(px(3.0))
                    .bg(kind_bg)
                    .text_size(px(sizes::LABEL - 1.5))
                    .text_color(kind_col)
                    .truncate()
                    .child(kind_label),
            ),
        )
        // Address
        .child(
            div()
                .w(px(120.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#010x}", addr.0)),
        )
        // Function/Symbol name
        .child(
            div()
                .flex_1()
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_symbol())
                .overflow_hidden()
                .truncate()
                .child(if func_name.is_empty() {
                    "—".to_owned()
                } else {
                    func_name.to_owned()
                }),
        )
        // Optional label
        .child(x.label.as_ref().map_or_else(
            || div().w(px(70.0)).into_any_element(),
            |lbl| {
                div()
                    .w(px(70.0))
                    .px_1()
                    .text_size(px(sizes::LABEL - 1.0))
                    .text_color(colors::syn_comment())
                    .font_family("JetBrains Mono")
                    .overflow_hidden()
                    .truncate()
                    .child(lbl.clone())
                    .into_any_element()
            },
        ))
}

fn xref_kind_colors(kind: XrefKind) -> (Hsla, Hsla) {
    match kind {
        XrefKind::Call => (
            colors::syn_mnemonic(),
            Hsla {
                h: 220.0 / 360.0,
                s: 0.5,
                l: 0.12,
                a: 0.7,
            },
        ),
        XrefKind::Jump => (
            colors::syn_immediate(),
            Hsla {
                h: 40.0 / 360.0,
                s: 0.5,
                l: 0.12,
                a: 0.7,
            },
        ),
        XrefKind::DataRead => (
            colors::syn_comment(),
            Hsla {
                h: 120.0 / 360.0,
                s: 0.4,
                l: 0.10,
                a: 0.7,
            },
        ),
        XrefKind::DataWrite => (
            colors::err(),
            Hsla {
                h: 0.0 / 360.0,
                s: 0.5,
                l: 0.12,
                a: 0.7,
            },
        ),
        XrefKind::DataRef => (
            colors::syn_label(),
            Hsla {
                h: 280.0 / 360.0,
                s: 0.4,
                l: 0.12,
                a: 0.7,
            },
        ),
        XrefKind::Fallthrough => (
            colors::text_muted(),
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.10,
                a: 0.5,
            },
        ),
    }
}

// ── Sub-components ────────────────────────────────────────────────────────────

fn xref_header(label: &str, count: usize) -> impl IntoElement {
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
                .text_size(px(sizes::PANEL - 1.0))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .overflow_hidden()
                .truncate()
                .child(label.to_owned()),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{count}")),
        )
}

fn direction_bar(
    show_to: bool,
    ui_arc: Arc<Mutex<UIState>>,
    bus: Arc<EventBus>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_1()
        .h(px(26.0))
        .px_2()
        .items_center()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(dir_btn(
            "xref-dir-callers",
            "Callers (->)",
            show_to,
            true,
            Arc::clone(&ui_arc),
            Arc::clone(&bus),
        ))
        .child(dir_btn(
            "xref-dir-callees",
            "Callees (<-)",
            !show_to,
            false,
            ui_arc,
            bus,
        ))
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .truncate()
                .child("X — toggle"),
        )
}

fn dir_btn(
    id: &'static str,
    label: &'static str,
    active: bool,
    set_show_to: bool,
    ui_arc: Arc<Mutex<UIState>>,
    bus: Arc<EventBus>,
) -> impl IntoElement {
    div()
        .id(SharedString::from(id))
        .px_2()
        .h(px(18.0))
        .rounded_sm()
        .flex()
        .items_center()
        .bg(if active {
            colors::accent()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if active {
            colors::accent()
        } else {
            colors::border()
        })
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(if active {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.05,
                a: 1.0,
            }
        } else {
            colors::text_muted()
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            {
                let mut ui = ui_arc.lock();
                ui.set_xref_show_to(set_show_to);
            }
            bus.send_command(UICommand::SwitchRightTab("xrefs".to_string()));
        })
        .truncate()
        .child(label)
}

fn filter_bar(filter: &str, ui_arc: Arc<Mutex<UIState>>) -> impl IntoElement {
    let has_text = !filter.is_empty();
    let display = if has_text {
        filter.to_string()
    } else {
        "Filter xrefs… (click to clear)".to_string()
    };
    div()
        .id(SharedString::from("xref-filter-bar"))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .h(px(22.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .id(SharedString::from("xref-filter-input"))
                .flex_1()
                .h(px(16.0))
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .px_1()
                .text_size(px(sizes::CODE - 1.5))
                .text_color(if has_text {
                    colors::text_primary()
                } else {
                    colors::text_muted()
                })
                .font_family("JetBrains Mono")
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .on_click(move |_: &ClickEvent, _, _| {
                    let mut ui = ui_arc.lock();
                    ui.xref_filter.clear();
                })
                .truncate()
                .child(display),
        )
}

fn stats_bar(stats: &XrefStats) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(22.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(stat_chip("CALL", stats.calls, colors::syn_mnemonic()))
        .child(stat_chip("JMP", stats.jumps, colors::syn_immediate()))
        .child(stat_chip("DATA", stats.data_refs, colors::syn_label()))
        .child(stat_chip("RD", stats.reads, colors::syn_comment()))
        .child(stat_chip("WR", stats.writes, colors::err()))
}

fn stat_chip(label: &'static str, count: usize, color: Hsla) -> impl IntoElement {
    if count == 0 {
        return div().into_any_element();
    }
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .child(
            div()
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .truncate()
                .child(label),
        )
        .child(
            div()
                .text_size(px(8.5))
                .text_color(color)
                .font_weight(FontWeight::BOLD)
                .truncate()
                .child(format!("{count}")),
        )
        .into_any_element()
}

fn col_headers(
    show_to: bool,
    sort_col: XrefSortCol,
    sort_asc: bool,
    pending: Arc<(AtomicU8, AtomicBool)>,
) -> impl IntoElement {
    let addr_label = if show_to { "From Addr" } else { "To Addr" };
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(sort_header(
            "xref-hdr-kind",
            "Kind",
            52.0,
            XrefSortCol::Kind,
            sort_col,
            sort_asc,
            Arc::clone(&pending),
        ))
        .child(sort_header(
            "xref-hdr-addr",
            addr_label,
            120.0,
            XrefSortCol::Addr,
            sort_col,
            sort_asc,
            Arc::clone(&pending),
        ))
        .child(sort_header_flex(
            "xref-hdr-symbol",
            "Symbol",
            XrefSortCol::Symbol,
            sort_col,
            sort_asc,
            Arc::clone(&pending),
        ))
        .child(sort_header(
            "xref-hdr-label",
            "Context",
            70.0,
            XrefSortCol::Label,
            sort_col,
            sort_asc,
            pending,
        ))
}

fn sort_indicator(active: bool, asc: bool) -> &'static str {
    if !active {
        ""
    } else if asc {
        " ▲"
    } else {
        " ▼"
    }
}

fn col_code(col: XrefSortCol) -> u8 {
    match col {
        XrefSortCol::Kind => 0,
        XrefSortCol::Addr => 1,
        XrefSortCol::Symbol => 2,
        XrefSortCol::Label => 3,
    }
}

fn sort_header(
    id: &'static str,
    label: &str,
    width: f32,
    this_col: XrefSortCol,
    sort_col: XrefSortCol,
    sort_asc: bool,
    pending: Arc<(AtomicU8, AtomicBool)>,
) -> impl IntoElement {
    let active = sort_col == this_col;
    let text = format!("{}{}", label, sort_indicator(active, sort_asc));
    div()
        .id(SharedString::from(id))
        .w(px(width))
        .px_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(if active {
            colors::text_primary()
        } else {
            colors::text_muted()
        })
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            pending.0.store(col_code(this_col), Ordering::Release);
            pending.1.store(true, Ordering::Release);
        })
        .truncate()
        .child(text)
}

fn sort_header_flex(
    id: &'static str,
    label: &str,
    this_col: XrefSortCol,
    sort_col: XrefSortCol,
    sort_asc: bool,
    pending: Arc<(AtomicU8, AtomicBool)>,
) -> impl IntoElement {
    let active = sort_col == this_col;
    let text = format!("{}{}", label, sort_indicator(active, sort_asc));
    div()
        .id(SharedString::from(id))
        .flex_1()
        .px_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(if active {
            colors::text_primary()
        } else {
            colors::text_muted()
        })
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            pending.0.store(col_code(this_col), Ordering::Release);
            pending.1.store(true, Ordering::Release);
        })
        .truncate()
        .child(text)
}

fn empty_state(has_target: bool) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .items_center()
        .justify_center()
        .text_color(colors::text_muted())
        .text_size(px(sizes::LABEL))
        .child(if has_target {
            "No cross-references found"
        } else {
            "Navigate to an address to see xrefs"
        })
}

fn toggle_row(
    show_to: bool,
    ui_arc: Arc<Mutex<UIState>>,
    bus: Arc<EventBus>,
) -> impl IntoElement {
    direction_bar(show_to, ui_arc, bus)
}

fn toggle_btn(label: &str, active: bool) -> impl IntoElement {
    div()
        .px_2()
        .h(px(16.0))
        .rounded_sm()
        .flex()
        .items_center()
        .bg(if active {
            colors::accent()
        } else {
            colors::bg_elevated()
        })
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(if active {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.05,
                a: 1.0,
            }
        } else {
            colors::text_muted()
        })
        .cursor_pointer()
        .truncate()
        .child(label.to_string())
}

#[doc(hidden)]
pub fn ensure_used_xrefs() {
    // Touch enum variants From and All.
    let variants = [XrefDisplay::To, XrefDisplay::From, XrefDisplay::All];
    for v in variants {
        match v {
            XrefDisplay::To | XrefDisplay::From | XrefDisplay::All => {}
        }
    }

    // Touch XrefsPanel methods.
    let mut panel = XrefsPanel::default();
    panel.set_target(Addr(0x1000));
    panel.toggle_direction();
    panel.on_scroll(1.0);
    panel.on_key_down(1);
    panel.invalidate_cache();
    panel.set_sort(XrefSortCol::Kind);
    panel.set_sort(XrefSortCol::Addr);
    panel.set_sort(XrefSortCol::Symbol);
    panel.set_sort(XrefSortCol::Label);
    let _sel: Option<Addr> = panel.selected_addr();
    let _c = col_code(XrefSortCol::Symbol);
    let _i = sort_indicator(true, false);

    // Touch standalone functions.
    let ui = Arc::new(Mutex::new(UIState::default()));
    let bus = Arc::new(EventBus::new());
    let _r = toggle_row(true, Arc::clone(&ui), Arc::clone(&bus));
    let _b = toggle_btn("test", false);
    let _fb = filter_bar("q", Arc::clone(&ui));
    let pending = Arc::new((AtomicU8::new(0), AtomicBool::new(false)));
    let _sh = sort_header(
        "h",
        "X",
        50.0,
        XrefSortCol::Addr,
        XrefSortCol::Addr,
        true,
        Arc::clone(&pending),
    );
    let _shf = sort_header_flex("hf", "Y", XrefSortCol::Symbol, XrefSortCol::Addr, false, pending);
}
