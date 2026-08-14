// ============================================================================
// ui/panels/symbols.rs — Symbols panel with filtering, sorting, navigation
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::cpu_pool::cpu_pool;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Addr, Symbol, SymbolKind};
use rayon::prelude::*;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, uniform_list, AnyElement, ClickEvent, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;

/// Zero-alloc ASCII-fold substring test. `needle_lower` must be lowercased
/// by the caller. Replaces `display_name().to_lowercase().contains(&q)`
/// which allocated a fresh String per row per keystroke (81k+ rows ×
/// keystrokes = OOM territory).
fn sym_contains_ignore_ascii_case(hay: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    let h = hay.as_bytes();
    let n = needle_lower.as_bytes();
    if n.len() > h.len() {
        return false;
    }
    for i in 0..=h.len() - n.len() {
        let mut ok = true;
        for j in 0..n.len() {
            if h[i + j].to_ascii_lowercase() != n[j] {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

/// Hex form `0x{:016x}` of `addr` matched against `needle` without any
/// heap allocation. `format!("{:#016x}", …)` per-row allocated a String
/// for every symbol on every keystroke; this writes into a stack buffer.
fn sym_addr_hex_contains(addr: u64, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nibble = ((addr >> ((15 - i) * 4)) & 0xF) as u8;
        buf[2 + i] = match nibble {
            0..=9 => b'0' + nibble,
            _ => b'a' + (nibble - 10),
        };
    }
    let s = std::str::from_utf8(&buf).unwrap_or("");
    s.contains(needle)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SymSort {
    #[default]
    Addr,
    Name,
    Kind,
    Size,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SymKindFilter {
    #[default]
    All,
    Functions,
    Data,
    Imports,
    Exports,
    Labels,
}

impl SymKindFilter {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Functions => "Funcs",
            Self::Data => "Data",
            Self::Imports => "Import",
            Self::Exports => "Export",
            Self::Labels => "Labels",
        }
    }

    pub const fn matches(self, kind: SymbolKind) -> bool {
        match self {
            Self::All => true,
            Self::Functions => matches!(kind, SymbolKind::Function | SymbolKind::Thunk),
            Self::Data => matches!(kind, SymbolKind::Data),
            Self::Imports => matches!(kind, SymbolKind::Import),
            Self::Exports => matches!(kind, SymbolKind::Export),
            Self::Labels => matches!(kind, SymbolKind::Label),
        }
    }

    pub const fn from_idx(i: u8) -> Self {
        match i {
            0 => Self::All,
            1 => Self::Functions,
            2 => Self::Data,
            3 => Self::Imports,
            4 => Self::Exports,
            _ => Self::Labels,
        }
    }
}

pub struct SymbolsPanel {
    pub vlist: VirtualListState,
    pub filter: String,
    pub sort: SymSort,
    pub sort_asc: bool,
    pub kind_filter: SymKindFilter,
    filtered_ids: Vec<u32>,
    cached_rev: u64,
    cached_filter: String,
    /// Shadow key derived from kind_filter + sort + sort_asc so refresh() rebuilds
    /// the list when those knobs change even if `rev` is unchanged.
    cached_knobs: u64,
}

impl Default for SymbolsPanel {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            filter: String::new(),
            sort: SymSort::default(),
            sort_asc: true,
            kind_filter: SymKindFilter::All,
            filtered_ids: Vec::new(),
            cached_rev: 0,
            cached_filter: String::new(),
            cached_knobs: 0,
        }
    }
}

impl SymbolsPanel {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        // Knob shadow: invalidate the cache when the user toggles a chip or sort
        // header even if rev hasn't bumped.
        let knobs: u64 = (self.kind_filter as u64)
            | ((self.sort as u64) << 8)
            | ((u64::from(self.sort_asc)) << 16);
        if self.cached_rev == rev
            && self.cached_filter == self.filter
            && self.cached_knobs == knobs
        {
            return;
        }
        self.cached_rev = rev;
        self.cached_filter = self.filter.clone();
        self.cached_knobs = knobs;

        let q = self.filter.to_lowercase();
        let kind_filter = self.kind_filter;
        let sort = self.sort;
        let sort_asc = self.sort_asc;

        // Snapshot to a Vec so rayon can split it. HashMap::values() is
        // not a `ParallelIterator`.
        let syms: Vec<&Symbol> = data.symbols.values().collect();

        let ids: Vec<u32> = cpu_pool().install(|| {
            syms.par_iter()
                .filter(|s| {
                    if !kind_filter.matches(s.kind) {
                        return false;
                    }
                    if q.is_empty() {
                        return true;
                    }
                    if sym_contains_ignore_ascii_case(s.display_name(), &q) {
                        return true;
                    }
                    sym_addr_hex_contains(s.addr.0, &q)
                })
                .map(|s| s.id)
                .collect()
        });

        // Materialize sort keys once, avoiding per-cmp HashMap lookups
        // and `format!("{:?}", kind)` per-cmp allocations.
        let symbols_map = &data.symbols;
        let mut keyed: Vec<(u32, u64, &str, u8, u64)> = ids
            .iter()
            .map(|&id| {
                let s = &symbols_map[&id];
                let kind_ord: u8 = match s.kind {
                    SymbolKind::Function => 0,
                    SymbolKind::Data => 1,
                    SymbolKind::Import => 2,
                    SymbolKind::Export => 3,
                    SymbolKind::Label => 4,
                    SymbolKind::Thunk => 5,
                    SymbolKind::Unknown => 6,
                };
                (id, s.addr.0, s.display_name(), kind_ord, s.size)
            })
            .collect();
        cpu_pool().install(|| {
            keyed.par_sort_unstable_by(|a, b| {
                let ord = match sort {
                    SymSort::Addr => a.1.cmp(&b.1),
                    SymSort::Name => a.2.cmp(b.2),
                    SymSort::Kind => a.3.cmp(&b.3),
                    SymSort::Size => a.4.cmp(&b.4),
                };
                if sort_asc {
                    ord
                } else {
                    ord.reverse()
                }
            });
        });
        self.filtered_ids = keyed.into_iter().map(|t| t.0).collect();
        self.vlist.total_rows = self.filtered_ids.len();
    }

    pub fn render<'a>(
        &'a self,
        data: &'a AppData,
        ui: &'a UIState,
        ui_arc: &Arc<Mutex<UIState>>,
        bus: &Arc<EventBus>,
        data_arc: Arc<RwLock<AppData>>,
    ) -> impl IntoElement + 'a {
        // DEADLOCK GUARD: caller already holds `state.ui.lock()` for the
        // entire panel-render pass. Re-locking `ui_arc` here on the same
        // thread freezes the UI (parking_lot::Mutex is not reentrant) and
        // Windows kills the process as "Non risponde". Read focus state
        // from the borrowed `&UIState` instead.
        let filter_focused = ui.sidebar_filter_focus == Some(2);
        let _ = ui_arc; // retained for click handlers below
        let win = self.vlist.window();
        let _ = (win.first, win.last);
        let total_rows = self.filtered_ids.len();

        // Snapshots for the `uniform_list` 'static closure.
        let filtered_ids: Vec<u32> = self.filtered_ids.clone();
        let selected_row = self.vlist.selected_row;
        let row_ui_arc = Arc::clone(ui_arc);
        let row_bus_arc = Arc::clone(bus);

        let render_range = move |range: std::ops::Range<usize>,
                                 _w: &mut gpui::Window,
                                 _cx: &mut gpui::App|
              -> Vec<AnyElement> {
            let d = data_arc.read();
            range
                .filter_map(|i| {
                    let sid = *filtered_ids.get(i)?;
                    let sym = d.symbols.get(&sid)?.clone();
                    let sel = selected_row == Some(i);
                    let xref_in = d.xrefs_to.get(&sym.addr.0).map_or(0, Vec::len);
                    let xref_out = d.xrefs_from.get(&sym.addr.0).map_or(0, Vec::len);
                    Some(
                        sym_row(&sym, sel, i, Arc::clone(&row_ui_arc), Arc::clone(&row_bus_arc), xref_in, xref_out)
                            .into_any_element(),
                    )
                })
                .collect()
        };

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_panel())
            .child(sym_hdr(
                "Symbols",
                self.filtered_ids.len(),
                data.symbols.len(),
            ))
            .child(sym_filter(&self.filter, filter_focused, bus))
            .child(sym_kind_bar(self.kind_filter, bus))
            .child(sym_col_hdr(self.sort, self.sort_asc, bus))
            .child(
                // True virtual scrolling via gpui::uniform_list — only the
                // ~30 rows in the viewport are rendered each frame.
                uniform_list(
                    SharedString::from("symbols-uniform"),
                    total_rows,
                    render_range,
                )
                .with_sizing_behavior(gpui::ListSizingBehavior::Auto)
                .h_full()
                .w_full()
                .flex_1(),
            )
    }

    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_down(&mut self, d: i64) {
        self.vlist.move_selection(d);
    }

    pub fn selected_addr(&self, data: &AppData) -> Option<Addr> {
        let row = self.vlist.selected_row?;
        let id = *self.filtered_ids.get(row)?;
        data.symbols.get(&id).map(|s| s.addr)
    }

    pub const fn cycle_sort(&mut self) {
        self.sort = match self.sort {
            SymSort::Addr => SymSort::Name,
            SymSort::Name => SymSort::Kind,
            SymSort::Kind => SymSort::Size,
            SymSort::Size => SymSort::Addr,
        };
        self.cached_rev = 0;
    }
}

// ── Row renderer ──────────────────────────────────────────────────────────────

fn sym_row(
    sym: &Symbol,
    sel: bool,
    row_idx: usize,
    ui_arc: Arc<Mutex<UIState>>,
    bus: Arc<EventBus>,
    xref_in: usize,
    xref_out: usize,
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

    let kind_letter = match sym.kind {
        SymbolKind::Function => "F",
        SymbolKind::Data => "D",
        SymbolKind::Import => "I",
        SymbolKind::Export => "E",
        SymbolKind::Label => "L",
        SymbolKind::Thunk => "T",
        SymbolKind::Unknown => "?",
    };
    let kind_fg = kind_fg_color(sym.kind);
    let badge_background = kind_bg_color(sym.kind);
    let addr = sym.addr;

    div()
        .id(SharedString::from(format!("sym-row-{row_idx}")))
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
        .on_click(move |_, _, _| {
            let mut ui = ui_arc.lock();
            ui.current_addr = addr;
            // Also retarget the xrefs panel so callers/callees of this
            // symbol show up immediately when the user selects it.
            ui.xref_target_addr = addr;
            drop(ui);
            // Notify the listing / hex / decompiler to scroll to this address.
            bus.send_command(UICommand::NavigateTo { addr, push_history: true });
        })
        // Kind badge
        .child(
            div().w(px(24.0)).px_1().child(
                div()
                    .w(px(16.0))
                    .h(px(16.0))
                    .rounded(px(3.0))
                    .bg(badge_background)
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_size(px(9.0))
                    .text_color(kind_fg)
                    .font_weight(FontWeight::BOLD)
                    .child(kind_letter),
            ),
        )
        // Address
        .child(
            div()
                .w(px(125.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#016x}", addr.0))
                .truncate(),
        )
        // Name
        .child(
            div()
                .flex_1()
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE))
                .text_color(sym_name_color(sym.kind))
                .overflow_hidden()
                .child(sym.display_name().to_owned())
                .truncate(),
        )
        // Size
        .child(
            div()
                .w(px(55.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(if sym.size > 0 {
                    format!("{:#x}", sym.size)
                } else {
                    String::new()
                })
                .truncate(),
        )
        // Xref counts (incoming / outgoing)
        .child(xref_count_cell(xref_in, xref_out))
}

/// Compact "in→out" cross-reference count badge shown on every symbol row.
/// Empty when the symbol has no references in either direction so the column
/// stays visually quiet for unreferenced labels.
fn xref_count_cell(xref_in: usize, xref_out: usize) -> impl IntoElement {
    let muted = colors::text_muted();
    let in_col = if xref_in == 0 {
        muted
    } else {
        colors::accent_cyan()
    };
    let out_col = if xref_out == 0 {
        muted
    } else {
        colors::accent_blue()
    };
    div()
        .w(px(72.0))
        .px_1()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .font_family("JetBrains Mono")
        .text_size(px(sizes::LABEL - 0.5))
        .child(
            div()
                .text_color(in_col)
                .child(format!("{xref_in}"))
                .truncate(),
        )
        .child(
            div()
                .text_color(muted)
                .child(crate::ui::widgets::icon::icon("arrow-right")),
        )
        .child(
            div()
                .text_color(out_col)
                .child(format!("{xref_out}"))
                .truncate(),
        )
}

const fn kind_fg_color(kind: SymbolKind) -> Hsla {
    match kind {
        SymbolKind::Label => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.7,
            a: 1.0,
        },
        SymbolKind::Unknown => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.5,
            a: 1.0,
        },
        SymbolKind::Function
        | SymbolKind::Data
        | SymbolKind::Import
        | SymbolKind::Export
        | SymbolKind::Thunk => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.9,
            a: 1.0,
        },
    }
}

fn kind_bg_color(kind: SymbolKind) -> Hsla {
    match kind {
        SymbolKind::Function => Hsla {
            h: 220.0 / 360.0,
            s: 0.6,
            l: 0.25,
            a: 1.0,
        },
        SymbolKind::Data => Hsla {
            h: 30.0 / 360.0,
            s: 0.6,
            l: 0.20,
            a: 1.0,
        },
        SymbolKind::Import => Hsla {
            h: 280.0 / 360.0,
            s: 0.5,
            l: 0.22,
            a: 1.0,
        },
        SymbolKind::Export => Hsla {
            h: 120.0 / 360.0,
            s: 0.5,
            l: 0.18,
            a: 1.0,
        },
        SymbolKind::Label => Hsla {
            h: 0.0 / 360.0,
            s: 0.0,
            l: 0.22,
            a: 1.0,
        },
        SymbolKind::Thunk => Hsla {
            h: 50.0 / 360.0,
            s: 0.5,
            l: 0.20,
            a: 1.0,
        },
        SymbolKind::Unknown => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.15,
            a: 1.0,
        },
    }
}

const fn sym_name_color(kind: SymbolKind) -> Hsla {
    match kind {
        SymbolKind::Function => colors::syn_symbol(),
        SymbolKind::Import => colors::syn_label(),
        SymbolKind::Export => colors::syn_immediate(),
        SymbolKind::Thunk => colors::syn_mnemonic(),
        _ => colors::text_primary(),
    }
}

// ── Sub-components ────────────────────────────────────────────────────────────

fn sym_hdr(title: &str, shown: usize, total: usize) -> impl IntoElement {
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
                .child(title.to_owned())
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(if shown == total {
                    format!("{total}")
                } else {
                    format!("{shown}/{total}")
                })
                .truncate(),
        )
}

fn sym_filter(f: &str, focused: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let b = Arc::clone(bus);
    div()
        .id(SharedString::from("sym-filter-bar"))
        .flex()
        .flex_row()
        .gap_1()
        .h(px(26.0))
        .px_2()
        .items_center()
        .bg(if focused { colors::bg_hover() } else { colors::bg_surface() })
        .border_b_1()
        .border_color(if focused { colors::accent() } else { colors::border() })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            b.send_command(UICommand::SidebarFilterFocus(2));
        })
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_muted())
                .child(crate::ui::widgets::icon::icon("search")),
        )
        .child(
            div()
                .flex_1()
                .h(px(18.0))
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .px_1()
                .text_size(px(sizes::CODE - 1.0))
                .text_color(if f.is_empty() {
                    colors::text_muted()
                } else {
                    colors::text_primary()
                })
                .font_family("JetBrains Mono")
                .child(if f.is_empty() {
                    if focused { "▌".to_string() } else { "Filter symbols…".to_string() }
                } else {
                    format!("{}{}", f, if focused { "▌" } else { "" })
                })
                .truncate(),
        )
}

fn sym_kind_bar(active: SymKindFilter, bus: &Arc<EventBus>) -> impl IntoElement {
    use SymKindFilter::{All, Data, Exports, Functions, Imports, Labels};
    let b_all = Arc::clone(bus);
    let b_fn = Arc::clone(bus);
    let b_dt = Arc::clone(bus);
    let b_imp = Arc::clone(bus);
    let b_exp = Arc::clone(bus);
    let b_lbl = Arc::clone(bus);
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .h(px(22.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(
            kind_chip("sym-chip-all", "All", active == All)
                .on_click(move |_: &ClickEvent, _, _| {
                    b_all.send_command(UICommand::SymSetKindFilter(0));
                }),
        )
        .child(
            kind_chip("sym-chip-funcs", "Funcs", active == Functions).on_click(
                move |_: &ClickEvent, _, _| {
                    b_fn.send_command(UICommand::SymSetKindFilter(1));
                },
            ),
        )
        .child(
            kind_chip("sym-chip-data", "Data", active == Data).on_click(
                move |_: &ClickEvent, _, _| {
                    b_dt.send_command(UICommand::SymSetKindFilter(2));
                },
            ),
        )
        .child(
            kind_chip("sym-chip-import", "Import", active == Imports).on_click(
                move |_: &ClickEvent, _, _| {
                    b_imp.send_command(UICommand::SymSetKindFilter(3));
                },
            ),
        )
        .child(
            kind_chip("sym-chip-export", "Export", active == Exports).on_click(
                move |_: &ClickEvent, _, _| {
                    b_exp.send_command(UICommand::SymSetKindFilter(4));
                },
            ),
        )
        .child(
            kind_chip("sym-chip-labels", "Labels", active == Labels).on_click(
                move |_: &ClickEvent, _, _| {
                    b_lbl.send_command(UICommand::SymSetKindFilter(5));
                },
            ),
        )
}

fn kind_chip(id: &'static str, label: &'static str, active: bool) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(id))
        .px_1()
        .h(px(14.0))
        .bg(if active {
            colors::accent()
        } else {
            colors::bg_base()
        })
        .border_1()
        .border_color(if active {
            colors::accent()
        } else {
            colors::border()
        })
        .rounded(px(3.0))
        .flex()
        .items_center()
        .text_size(px(8.5))
        .text_color(if active {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.95,
                a: 1.0,
            }
        } else {
            colors::text_muted()
        })
        .cursor_pointer()
        .child(label)
}

fn sym_col_hdr(sort: SymSort, asc: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let b_addr = Arc::clone(bus);
    let b_name = Arc::clone(bus);
    let b_size = Arc::clone(bus);
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .w(px(24.0))
                .px_1()
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .child("T")
                .truncate(),
        )
        .child(
            sym_col_hdr_cell(
                "sym-hdr-addr",
                "Address",
                125.0,
                sort == SymSort::Addr,
                asc,
            )
            .on_click(move |_: &ClickEvent, _, _| {
                b_addr.send_command(UICommand::SymSortBy(0));
            }),
        )
        .child(
            sym_col_hdr_flex("sym-hdr-name", "Name", sort == SymSort::Name, asc).on_click(
                move |_: &ClickEvent, _, _| {
                    b_name.send_command(UICommand::SymSortBy(1));
                },
            ),
        )
        .child(
            sym_col_hdr_cell("sym-hdr-size", "Size", 55.0, sort == SymSort::Size, asc).on_click(
                move |_: &ClickEvent, _, _| {
                    b_size.send_command(UICommand::SymSortBy(3));
                },
            ),
        )
        .child(
            div()
                .w(px(72.0))
                .px_1()
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Xrefs")
                .truncate(),
        )
}

fn sym_col_hdr_cell(
    id: &'static str,
    label: &'static str,
    w: f32,
    active: bool,
    asc: bool,
) -> gpui::Stateful<gpui::Div> {
    let arrow = if active {
        if asc {
            " ^"
        } else {
            " v"
        }
    } else {
        ""
    };
    div()
        .id(SharedString::from(id))
        .w(px(w))
        .px_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(if active {
            colors::accent()
        } else {
            colors::text_muted()
        })
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(format!("{label}{arrow}"))
        .truncate()
}

fn sym_col_hdr_flex(
    id: &'static str,
    label: &'static str,
    active: bool,
    asc: bool,
) -> gpui::Stateful<gpui::Div> {
    let arrow = if active {
        if asc {
            " ^"
        } else {
            " v"
        }
    } else {
        ""
    };
    div()
        .id(SharedString::from(id))
        .flex_1()
        .px_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(if active {
            colors::accent()
        } else {
            colors::text_muted()
        })
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(format!("{label}{arrow}"))
        .truncate()
}

use gpui::{FontWeight, Hsla};

#[doc(hidden)]
pub fn ensure_used_symbols() {
    // Touch SymSort::Kind variant.
    match SymSort::Kind {
        SymSort::Addr | SymSort::Name | SymSort::Kind | SymSort::Size => {}
    }

    // Touch SymKindFilter::label method on every variant.
    let l0 = SymKindFilter::All.label();
    let _l1 = SymKindFilter::Functions.label();
    let _l2 = SymKindFilter::Data.label();
    let _l3 = SymKindFilter::Imports.label();
    let _l4 = SymKindFilter::Exports.label();
    let _l5 = SymKindFilter::Labels.label();
    debug_assert_eq!(l0, "All");

    // Touch SymbolsPanel methods: on_scroll, on_key_down, selected_addr, cycle_sort.
    let mut panel = SymbolsPanel::default();
    panel.on_scroll(0.0);
    panel.on_key_down(0);
    panel.cycle_sort();
    let data = AppData::new();
    let addr_opt: Option<Addr> = panel.selected_addr(&data);
    debug_assert!(addr_opt.is_none());
}
