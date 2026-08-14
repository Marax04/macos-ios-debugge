// ============================================================================
// ui/panels/strings.rs — Strings panel with virtual list and navigation
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::cpu_pool::cpu_pool;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Addr, StringEntry, StringKind};
use rayon::prelude::*;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, uniform_list, AnyElement, ClickEvent, FontWeight, Hsla, InteractiveElement,
    IntoElement, ParentElement, SharedString, StatefulInteractiveElement, Styled,
};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;

/// Case-insensitive substring test that does NOT allocate. `needle_lower`
/// must already be lowercased by the caller. Some embedded strings inside
/// binaries are MB-sized; `s.value.to_lowercase()` allocated that whole
/// buffer per-row per-keystroke and could OOM. ASCII-only fold matches
/// the previous behavior for the vast majority of strings.
fn str_contains_ignore_ascii_case(hay: &str, needle_lower: &str) -> bool {
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

/// Encoding categories for filtering strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StringEncFilter {
    #[default]
    All,
    Ascii,
    Utf16,
    Utf8,
}

impl StringEncFilter {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Ascii => "ASCII",
            Self::Utf16 => "UTF-16",
            Self::Utf8 => "UTF-8",
        }
    }

    /// Advance to the next preset, wrapping back to `All`.
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::Ascii,
            Self::Ascii => Self::Utf16,
            Self::Utf16 => Self::Utf8,
            Self::Utf8 => Self::All,
        }
    }
}

/// Minimum length filter for strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MinLenFilter {
    Len4,
    #[default]
    Len6,
    Len10,
    Len20,
    Len50,
}

impl MinLenFilter {
    pub const fn value(self) -> usize {
        match self {
            Self::Len4 => 4,
            Self::Len6 => 6,
            Self::Len10 => 10,
            Self::Len20 => 20,
            Self::Len50 => 50,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Len4 => "≥4",
            Self::Len6 => "≥6",
            Self::Len10 => "≥10",
            Self::Len20 => "≥20",
            Self::Len50 => "≥50",
        }
    }

    /// Advance to the next preset, wrapping back to the smallest.
    pub const fn next(self) -> Self {
        match self {
            Self::Len4 => Self::Len6,
            Self::Len6 => Self::Len10,
            Self::Len10 => Self::Len20,
            Self::Len20 => Self::Len50,
            Self::Len50 => Self::Len4,
        }
    }
}

/// Column the Strings panel is sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StrSort {
    Enc,
    #[default]
    Addr,
    Len,
    Value,
    Xrefs,
}

pub struct StringsPanel {
    pub vlist: VirtualListState,
    pub filter: String,
    pub enc_filter: StringEncFilter,
    pub min_len: MinLenFilter,
    pub show_xrefs: bool,
    pub sort: StrSort,
    pub sort_asc: bool,
    filtered_ids: Vec<usize>, // indices into AppData::strings
    cached_rev: u64,
    cached_filter: String,
    /// Shadow key derived from min_len / enc_filter / sort / sort_asc / show_xrefs
    /// so refresh re-runs when any chip/toggle is touched without a rev bump.
    cached_knobs: u64,
    /// Row index whose inline `…` context menu is open, if any.
    pub row_menu: Option<usize>,
}

impl Default for StringsPanel {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            filter: String::new(),
            enc_filter: StringEncFilter::All,
            min_len: MinLenFilter::Len6,
            show_xrefs: false,
            sort: StrSort::default(),
            sort_asc: true,
            filtered_ids: Vec::new(),
            cached_rev: 0,
            cached_filter: String::new(),
            cached_knobs: 0,
            row_menu: None,
        }
    }
}

impl StringsPanel {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        // Knob shadow: any chip / sort / xref toggle should rebuild the list
        // even when the underlying strings revision is unchanged.
        let knobs: u64 = (self.min_len as u64)
            | ((self.enc_filter as u64) << 8)
            | ((self.sort as u64) << 16)
            | ((u64::from(self.sort_asc)) << 24)
            | ((u64::from(self.show_xrefs)) << 25);
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
        let min_len = self.min_len.value();
        let enc = self.enc_filter;
        let sort = self.sort;
        let sort_asc = self.sort_asc;

        // Parallel filter. `s.value.to_lowercase()` allocates a fresh
        // String per entry — for some binaries that's MB-sized strings,
        // which thrashed the allocator and could OOM. Use the zero-alloc
        // ASCII-fold helper instead. Filter runs across cpu_pool workers.
        let mut ids: Vec<usize> = cpu_pool().install(|| {
            data.strings
                .par_iter()
                .enumerate()
                .filter_map(|(i, s)| {
                    if (s.len as usize) < min_len {
                        return None;
                    }
                    let pass_enc = match enc {
                        StringEncFilter::All => true,
                        StringEncFilter::Ascii => s.kind == StringKind::Ascii,
                        StringEncFilter::Utf16 => {
                            s.kind == StringKind::Utf16Le || s.kind == StringKind::Utf16Be
                        }
                        StringEncFilter::Utf8 => s.kind == StringKind::Utf8,
                    };
                    if !pass_enc {
                        return None;
                    }
                    if !q.is_empty() && !str_contains_ignore_ascii_case(&s.value, &q) {
                        return None;
                    }
                    Some(i)
                })
                .collect()
        });

        // Materialize sort keys once instead of paying allocator costs per
        // comparator call. `format!("{:?}", kind)` per cmp was the worst
        // offender — millions of String allocs during a 100k-entry sort.
        let xrefs_to = &data.xrefs_to;
        let mut keyed: Vec<(usize, u64, u64, u32, &str, u8)> = ids
            .iter()
            .map(|&i| {
                let s = &data.strings[i];
                let xc = xrefs_to.get(&s.addr.0).map_or(0u64, |v| v.len() as u64);
                let kind_ord: u8 = match s.kind {
                    StringKind::Ascii => 0,
                    StringKind::Utf8 => 1,
                    StringKind::Utf16Le => 2,
                    StringKind::Utf16Be => 3,
                    StringKind::Pascal => 4,
                };
                (i, s.addr.0, xc, s.len, s.value.as_str(), kind_ord)
            })
            .collect();
        cpu_pool().install(|| {
            keyed.par_sort_unstable_by(|a, b| {
                let ord = match sort {
                    StrSort::Enc => a.5.cmp(&b.5),
                    StrSort::Addr => a.1.cmp(&b.1),
                    StrSort::Len => a.3.cmp(&b.3),
                    StrSort::Value => a.4.cmp(b.4),
                    StrSort::Xrefs => a.2.cmp(&b.2),
                };
                if sort_asc {
                    ord
                } else {
                    ord.reverse()
                }
            });
        });
        ids = keyed.into_iter().map(|t| t.0).collect();

        self.filtered_ids = ids;
        self.vlist.total_rows = self.filtered_ids.len();
    }

    pub fn string_index_at_row(&self, row: usize) -> Option<usize> {
        self.filtered_ids.get(row).copied()
    }

    pub fn scroll_to_addr(&mut self, data: &AppData, addr: Addr) {
        if let Some(row) = self
            .filtered_ids
            .iter()
            .position(|&idx| data.strings.get(idx).is_some_and(|s| s.addr == addr))
        {
            self.vlist.scroll_to_row(row);
        }
    }

    pub fn render<'a>(
        &'a self,
        data: &'a AppData,
        ui: &'a UIState,
        ui_arc: &Arc<Mutex<UIState>>,
        bus: &Arc<EventBus>,
        data_arc: Arc<RwLock<AppData>>,
    ) -> impl IntoElement + 'a {
        // DEADLOCK GUARD: caller in app.rs already holds `state.ui.lock()`
        // for the whole panel-render pass. Re-locking `ui_arc` here on the
        // same thread freezes the UI (parking_lot::Mutex is not reentrant).
        // Read focus state from the borrowed `&UIState` instead.
        let filter_focused = ui.sidebar_filter_focus == Some(1);
        let _ = ui_arc; // kept in the signature for click handlers below
        let win = self.vlist.window();
        let _ = (win.first, win.last);
        let show_xrefs = self.show_xrefs;
        let total_rows = self.filtered_ids.len();

        // Snapshots for the `uniform_list` 'static closure.
        let filtered_ids: Vec<usize> = self.filtered_ids.clone();
        let selected_row = self.vlist.selected_row;
        let row_menu = self.row_menu;
        let row_ui_arc = Arc::clone(ui_arc);
        let row_bus = Arc::clone(bus);

        let render_range = move |range: std::ops::Range<usize>,
                                 _w: &mut gpui::Window,
                                 _cx: &mut gpui::App|
              -> Vec<AnyElement> {
            let d = data_arc.read();
            range
                .filter_map(|i| {
                    let str_idx = *filtered_ids.get(i)?;
                    let s = d.strings.get(str_idx)?.clone();
                    let sel = selected_row == Some(i);
                    let xref_count = if show_xrefs {
                        d.xrefs_to.get(&s.addr.0).map_or(0, Vec::len)
                    } else {
                        0
                    };
                    let menu_open = row_menu == Some(i);
                    Some(
                        string_row(
                            &s,
                            sel,
                            i,
                            show_xrefs,
                            xref_count,
                            Arc::clone(&row_ui_arc),
                            Arc::clone(&row_bus),
                            menu_open,
                        )
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
            .child(panel_hdr(
                "Strings",
                self.filtered_ids.len(),
                data.strings.len(),
            ))
            .child(str_filter_bar(&self.filter, filter_focused, bus))
            .child(str_option_bar(
                self.min_len,
                self.enc_filter,
                self.show_xrefs,
                bus,
            ))
            .child(str_col_hdr(show_xrefs, self.sort, self.sort_asc, bus))
            .child(
                // True virtual scrolling via gpui::uniform_list — only the
                // ~30 rows currently in viewport are rendered each frame.
                uniform_list(
                    SharedString::from("strings-uniform"),
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
        let idx = *self.filtered_ids.get(row)?;
        data.strings.get(idx).map(|s| s.addr)
    }
}

// ── Row renderer ──────────────────────────────────────────────────────────────

fn string_row(
    s: &StringEntry,
    selected: bool,
    row_idx: usize,
    show_xrefs: bool,
    xref_count: usize,
    ui_arc: Arc<Mutex<UIState>>,
    bus: Arc<EventBus>,
    menu_open: bool,
) -> impl IntoElement {
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
    let border_color = if selected {
        colors::accent()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    // PANIC GUARD: `&s.value[..58]` crashes if byte 58 lands in the middle
    // of a UTF-8 multi-byte char. Many strings extracted from a binary are
    // valid UTF-8 with non-ASCII bytes (file paths, error messages, embedded
    // protocol blobs), so this used to crash the whole panel on tab switch.
    // Walk back to the nearest char boundary before slicing.
    let truncated = if s.value.len() > 60 {
        let mut end = 58.min(s.value.len());
        while end > 0 && !s.value.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s.value[..end])
    } else {
        s.value.clone()
    };

    let addr = s.addr;
    let len = s.len;
    let is_wide = s.value.contains('\u{0}'); // crude UTF-16 heuristic

    div()
        .id(SharedString::from(format!("str-row-{row_idx}")))
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
        .on_click({
            let bus = Arc::clone(&bus);
            move |_, _, _| {
                {
                    let mut ui = ui_arc.lock();
                    ui.current_addr = addr;
                }
                bus.send_command(UICommand::NavigateTo {
                    addr,
                    push_history: true,
                });
                bus.send_command(UICommand::SwitchRightTab("xrefs".to_string()));
            }
        })
        // Encoding badge
        .child(
            div().w(px(44.0)).px_1().child(
                div()
                    .px_1()
                    .rounded(px(3.0))
                    .bg(if is_wide {
                        Hsla {
                            h: 200.0 / 360.0,
                            s: 0.4,
                            l: 0.15,
                            a: 0.6,
                        }
                    } else {
                        Hsla {
                            h: 120.0 / 360.0,
                            s: 0.3,
                            l: 0.12,
                            a: 0.5,
                        }
                    })
                    .text_size(px(sizes::LABEL - 1.5))
                    .text_color(if is_wide {
                        colors::syn_label()
                    } else {
                        colors::ok()
                    })
                    .truncate()
                    .child(if is_wide { "U16" } else { "ASC" }),
            ),
        )
        // Address column
        .child(
            div()
                .w(px(120.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(crate::ui::widgets::copyable::copyable_addr_global(addr.0)),
        )
        // Length column
        .child(
            div()
                .w(px(40.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{len}")),
        )
        // String value
        .child(
            div()
                .flex_1()
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE))
                .text_color(colors::syn_symbol())
                .overflow_hidden()
                .truncate()
                .child(format!("\"{truncated}\"")),
        )
        // Optional xrefs-to count, gated by the `show_xrefs` toggle so the
        // user can opt in to a denser layout when triaging references.
        .child(if show_xrefs {
            div()
                .w(px(36.0))
                .px_1()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(if xref_count > 0 {
                    colors::syn_label()
                } else {
                    colors::text_muted()
                })
                .truncate()
                .child(format!("x{xref_count}"))
                .into_any_element()
        } else {
            div().into_any_element()
        })
        // Trailing context-menu trigger ("…"). Clicking toggles the inline menu
        // for this row; the menu items dispatch StringsRowAction back to app.rs.
        .child({
            let menu_bus = Arc::clone(&bus);
            div()
                .id(SharedString::from(format!("str-row-menu-btn-{row_idx}")))
                .w(px(20.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child("…")
                .on_click(move |_: &ClickEvent, _, _| {
                    menu_bus.send_command(UICommand::StringsRowMenu(row_idx));
                })
        })
        .child(if menu_open {
            row_context_menu(row_idx, &bus).into_any_element()
        } else {
            div().into_any_element()
        })
}

fn row_context_menu(row_idx: usize, bus: &Arc<EventBus>) -> impl IntoElement {
    let entries: [(&'static str, u8, &'static str); 5] = [
        ("Copy text", 0, "copy-text"),
        ("Copy address", 1, "copy-addr"),
        ("Navigate", 2, "nav"),
        ("Find xrefs", 3, "xrefs"),
        ("Add bookmark", 4, "bookmark"),
    ];
    let mut menu = div()
        .id(SharedString::from(format!("str-row-menu-{row_idx}")))
        .flex()
        .flex_col()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(3.0));
    for (label, kind, tag) in entries {
        let b = Arc::clone(bus);
        menu = menu.child(
            div()
                .id(SharedString::from(format!(
                    "str-row-menu-{row_idx}-{tag}"
                )))
                .px_2()
                .h(px(18.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child(label)
                .on_click(move |_: &ClickEvent, _, _| {
                    b.send_command(UICommand::StringsRowAction(kind, row_idx));
                    b.send_command(UICommand::StringsRowMenu(usize::MAX));
                }),
        );
    }
    menu
}

fn str_col_hdr(
    show_xrefs: bool,
    sort: StrSort,
    asc: bool,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let b_enc = Arc::clone(bus);
    let b_addr = Arc::clone(bus);
    let b_len = Arc::clone(bus);
    let b_val = Arc::clone(bus);
    let b_xref = Arc::clone(bus);
    let mut hdr = div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(
            col_label("str-hdr-enc", "Enc", 44.0, sort == StrSort::Enc, asc).on_click(
                move |_: &ClickEvent, _, _| b_enc.send_command(UICommand::StringsSortBy(0)),
            ),
        )
        .child(
            col_label("str-hdr-addr", "Address", 120.0, sort == StrSort::Addr, asc).on_click(
                move |_: &ClickEvent, _, _| b_addr.send_command(UICommand::StringsSortBy(1)),
            ),
        )
        .child(
            col_label("str-hdr-len", "Len", 40.0, sort == StrSort::Len, asc).on_click(
                move |_: &ClickEvent, _, _| b_len.send_command(UICommand::StringsSortBy(2)),
            ),
        )
        .child(
            col_label_flex("str-hdr-val", "Value", sort == StrSort::Value, asc).on_click(
                move |_: &ClickEvent, _, _| b_val.send_command(UICommand::StringsSortBy(3)),
            ),
        );
    if show_xrefs {
        hdr = hdr.child(
            col_label("str-hdr-xref", "Xrefs", 36.0, sort == StrSort::Xrefs, asc).on_click(
                move |_: &ClickEvent, _, _| b_xref.send_command(UICommand::StringsSortBy(4)),
            ),
        );
    }
    hdr
}

fn col_label(
    id: &'static str,
    text: &'static str,
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
        .truncate()
        .child(format!("{text}{arrow}"))
}

fn col_label_flex(
    id: &'static str,
    text: &'static str,
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
        .truncate()
        .child(format!("{text}{arrow}"))
}

fn panel_hdr(title: &str, shown: usize, total: usize) -> impl IntoElement {
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
                .child(title.to_owned()),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(if shown == total {
                    format!("{total}")
                } else {
                    format!("{shown}/{total}")
                }),
        )
}

fn str_filter_bar(f: &str, focused: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let b = Arc::clone(bus);
    div()
        .id(SharedString::from("str-filter-bar"))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .h(px(26.0))
        .px_2()
        .bg(if focused { colors::bg_hover() } else { colors::bg_surface() })
        .border_b_1()
        .border_color(if focused { colors::accent() } else { colors::border() })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            b.send_command(UICommand::SidebarFilterFocus(1));
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
                .truncate()
                .child(if f.is_empty() {
                    if focused { "▌".to_string() } else { "Filter strings…".to_string() }
                } else {
                    format!("{}{}", f, if focused { "▌" } else { "" })
                }),
        )
}

fn str_option_bar(
    min_len: MinLenFilter,
    enc: StringEncFilter,
    show_xrefs: bool,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let min_bus = Arc::clone(bus);
    let enc_bus = Arc::clone(bus);
    let xref_bus = Arc::clone(bus);
    let refresh_bus = Arc::clone(bus);
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
        .child(
            div()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .truncate()
                .child("Min:"),
        )
        .child(option_chip("strings-min-len-chip", min_len.label(), true).on_click(
            move |_: &ClickEvent, _, _| {
                min_bus.send_command(UICommand::StringsCycleMinLen);
            },
        ))
        .child(div().w(px(1.0)).h(px(12.0)).bg(colors::border()))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .truncate()
                .child("Enc:"),
        )
        .child(
            option_chip("strings-enc-chip", enc.label(), enc == StringEncFilter::All).on_click(
                move |_: &ClickEvent, _, _| {
                    enc_bus.send_command(UICommand::StringsCycleEnc);
                },
            ),
        )
        .child(div().w(px(1.0)).h(px(12.0)).bg(colors::border()))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .truncate()
                .child("Xrefs:"),
        )
        .child(
            option_chip(
                "strings-xrefs-chip",
                if show_xrefs { "On" } else { "Off" },
                show_xrefs,
            )
            .on_click(move |_: &ClickEvent, _, _| {
                xref_bus.send_command(UICommand::StringsToggleXrefs);
            }),
        )
        .child(div().w(px(1.0)).h(px(12.0)).bg(colors::border()))
        .child(
            option_chip("strings-refresh-chip", "\u{21bb} Refresh", false).on_click(
                move |_: &ClickEvent, _, _| {
                    refresh_bus.send_command(UICommand::StringsRefresh);
                },
            ),
        )
}

fn option_chip(id: &'static str, label: &'static str, active: bool) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(id))
        .px_1()
        .h(px(14.0))
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
        .rounded(px(3.0))
        .flex()
        .items_center()
        .text_size(px(9.0))
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
        .hover(|s| s.bg(colors::bg_hover()))
        .truncate()
        .child(label)
}

#[doc(hidden)]
pub fn ensure_used_strings() {
    // Touch enum variants for StringEncFilter.
    for v in [
        StringEncFilter::All,
        StringEncFilter::Ascii,
        StringEncFilter::Utf16,
        StringEncFilter::Utf8,
    ] {
        match v {
            StringEncFilter::All
            | StringEncFilter::Ascii
            | StringEncFilter::Utf16
            | StringEncFilter::Utf8 => {}
        }
        let _ = v.label();
    }

    // Touch enum variants for MinLenFilter.
    for v in [
        MinLenFilter::Len4,
        MinLenFilter::Len6,
        MinLenFilter::Len10,
        MinLenFilter::Len20,
        MinLenFilter::Len50,
    ] {
        match v {
            MinLenFilter::Len4
            | MinLenFilter::Len6
            | MinLenFilter::Len10
            | MinLenFilter::Len20
            | MinLenFilter::Len50 => {}
        }
        let _ = v.value();
        let _ = v.label();
    }

    // Touch StringsPanel fields and methods.
    let mut panel = StringsPanel::default();
    let _ = panel.show_xrefs;
    panel.show_xrefs = true;
    debug_assert!(panel.show_xrefs);
    panel.row_menu = Some(0);
    let _ = panel.row_menu;
    panel.row_menu = None;
    let data = AppData::new();
    let _ = panel.string_index_at_row(0);
    panel.scroll_to_addr(&data, Addr(0));
    panel.on_scroll(0.0);
    panel.on_key_down(0);
    let _ = panel.selected_addr(&data);
}
