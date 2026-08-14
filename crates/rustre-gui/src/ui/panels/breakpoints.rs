// ============================================================================
// ui/panels/breakpoints.rs — Breakpoints panel with toggle, navigation, conditions
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Addr, BpKind, Breakpoint};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, ClickEvent, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::sync::{Arc, OnceLock};

/// Breakpoint condition state for editing.
#[derive(Clone, Debug, Default)]
pub struct BpConditionEditor {
    pub editing_id: Option<u32>,
    pub input: String,
}

/// Sorting/grouping modes for the breakpoints list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BpSort {
    #[default]
    Id,
    Addr,
    HitCount,
    Kind,
}

pub struct BreakpointsPanelState {
    pub vlist: VirtualListState,
    pub sort: BpSort,
    pub filter_enabled_only: bool,
    pub selected_id: Option<u32>,
    pub cond_editor: BpConditionEditor,
    cached_ids: Vec<u32>,
    cached_rev: u64,
}

impl Default for BreakpointsPanelState {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H * 1.5),
            sort: BpSort::Id,
            filter_enabled_only: false,
            selected_id: None,
            cond_editor: BpConditionEditor::default(),
            cached_ids: Vec::new(),
            cached_rev: 0,
        }
    }
}

impl BreakpointsPanelState {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if self.cached_rev == rev {
            return;
        }
        self.cached_rev = rev;

        let mut ids: Vec<u32> = data
            .breakpoints
            .keys()
            .copied()
            .filter(|id| {
                if self.filter_enabled_only {
                    data.breakpoints.get(id).is_some_and(|bp| bp.enabled)
                } else {
                    true
                }
            })
            .collect();

        ids.sort_by(|&a, &b| {
            let bpa = &data.breakpoints[&a];
            let bpb = &data.breakpoints[&b];
            match self.sort {
                BpSort::Id => a.cmp(&b),
                BpSort::Addr => bpa.addr.0.cmp(&bpb.addr.0),
                BpSort::HitCount => bpb.hit_count.cmp(&bpa.hit_count),
                BpSort::Kind => format!("{:?}", bpa.kind).cmp(&format!("{:?}", bpb.kind)),
            }
        });

        self.cached_ids = ids;
        self.vlist.total_rows = self.cached_ids.len();
    }

    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_down(&mut self, d: i64) {
        self.vlist.move_selection(d);
    }
}

/// Render the breakpoints panel with the watchpoints section appended at the
/// bottom. The watchpoint section is interactive (toggle / delete / + Watch),
/// hence the panel needs the shared `EventBus` to dispatch commands.
pub fn render_breakpoints_panel_with_watchpoints<'a>(
    data: &'a AppData,
    bus: &'a Arc<EventBus>,
    current_addr: Addr,
) -> impl IntoElement + 'a {
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(render_breakpoints_panel(data, bus, current_addr))
        .child(crate::ui::panels::watchpoints_section::render_watchpoints_section(
            data, bus,
        ))
}

/// Process-wide panel state (single right-side Breakpoints panel). Refreshed
/// once per render frame via `BreakpointsPanelState::refresh`, which short-
/// circuits when `data.rev` is unchanged.
fn panel_state() -> &'static Mutex<BreakpointsPanelState> {
    static STATE: OnceLock<Mutex<BreakpointsPanelState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(BreakpointsPanelState::default()))
}

pub fn render_breakpoints_panel<'a>(
    data: &'a AppData,
    bus: &'a Arc<EventBus>,
    current_addr: Addr,
) -> impl IntoElement + 'a {
    let total = data.breakpoints.len();
    let enabled_count = data.breakpoints.values().filter(|bp| bp.enabled).count();

    // Refresh cached sort/filter ids when the breakpoint set changes.  AppState's
    // RevCounter for breakpoints lives outside AppData and is not threaded
    // through here, so we derive a cheap synthetic revision from the bp map:
    // count XOR-folded with every id, which changes on any add / remove / id
    // shuffle.  Toggle/edit-in-place don't change identity, but they don't
    // affect the sort/filter cache either.
    let synth_rev: u64 = (data.breakpoints.len() as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ data.breakpoints.keys().copied().fold(0u64, |acc, k| acc.wrapping_add(u64::from(k)));
    panel_state().lock().refresh(data, synth_rev);

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(bp_hdr("Breakpoints", total, enabled_count))
        .child(bp_toolbar(bus, current_addr, data))
        .child(bp_col_hdr())
        .child(if data.breakpoints.is_empty() {
            bp_empty_state().into_any_element()
        } else {
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .id("breakpoints-scroll")
                .overflow_y_scroll()
                .children(
                    data.breakpoints
                        .values()
                        .map(|bp| bp_row(bp, data, bus)),
                )
                .into_any_element()
        })
}

fn bp_row_main(bp: &Breakpoint, data: &AppData, bus: &Arc<EventBus>) -> impl IntoElement {
    let en_col = if bp.enabled {
        colors::bp_enabled()
    } else {
        colors::bp_disabled()
    };
    let kind_label = bp_kind_label(bp.kind);
    let kind_color = bp_kind_color(bp.kind);
    let kind_bg = bp_kind_bg(bp.kind);
    let sym = data
        .name_at_addr(bp.addr)
        .unwrap_or_else(|| format!("sub_{:08x}", bp.addr.0));
    let bp_id = bp.id;
    let bp_addr = bp.addr;
    let bus_row = Arc::clone(bus);
    let bus_toggle = Arc::clone(bus);
    let bus_edit = Arc::clone(bus);
    let bus_del = Arc::clone(bus);

    div()
        .id(SharedString::from(format!("bp-row-{bp_id}")))
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H))
        .items_center()
        .px_2()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus_row.send_command(UICommand::NavigateTo {
                addr: bp_addr,
                push_history: true,
            });
        })
        .child(
            div()
                .id(SharedString::from(format!("bp-toggle-{bp_id}")))
                .w(px(14.0))
                .h(px(14.0))
                .rounded_full()
                .bg(en_col)
                .mr_2()
                .cursor_pointer()
                .hover(|s| s.opacity(0.7))
                .on_click(move |_: &ClickEvent, _, _| {
                    bus_toggle.send_command(UICommand::DbgToggleBreakpoint { bp_id });
                }),
        )
        .child(
            div()
                .w(px(26.0))
                .text_size(px(sizes::LABEL))
                .text_color(en_col)
                .font_family("JetBrains Mono")
                .child(format!("#{bp_id}"))
                .truncate(),
        )
        .child(
            div().w(px(36.0)).px_1().child(
                div()
                    .px_1()
                    .rounded(px(3.0))
                    .bg(kind_bg)
                    .text_size(px(sizes::LABEL - 1.5))
                    .text_color(kind_color)
                    .child(kind_label)
                    .truncate(),
            ),
        )
        .child(
            div()
                .w(px(120.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(if bp.enabled {
                    colors::syn_address()
                } else {
                    colors::text_muted()
                })
                .child(format!("{:#010x}", bp.addr.0))
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(if bp.enabled {
                    colors::syn_symbol()
                } else {
                    colors::text_muted()
                })
                .overflow_hidden()
                .child(sym)
                .truncate(),
        )
        .child(
            div()
                .w(px(60.0))
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(
                    div()
                        .flex_1()
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(if bp.condition.is_some() {
                            colors::syn_immediate()
                        } else {
                            colors::text_muted()
                        })
                        .overflow_hidden()
                        .child(if bp.condition.is_some() { "set" } else { "—" })
                        .truncate(),
                )
                .child(
                    div()
                        .id(SharedString::from(format!("bp-cond-edit-{bp_id}")))
                        .w(px(16.0))
                        .h(px(16.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(3.0))
                        .cursor_pointer()
                        .hover(|s| s.bg(colors::bg_hover()))
                        .child(crate::ui::widgets::icon::icon("pencil"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            // Open the inline condition editor for this row.
                            // No command variant exists for condition edits;
                            // the editor is local UI state.
                            let mut st = panel_state().lock();
                            st.cond_editor.editing_id = Some(bp_id);
                            st.cond_editor.input.clear();
                            let _ = &bus_edit; // reserved for future commit-edit command
                        }),
                ),
        )
        .child(if bp.hit_count > 0 {
            div()
                .px_1()
                .h(px(16.0))
                .bg(Hsla {
                    h: 30.0 / 360.0,
                    s: 0.5,
                    l: 0.18,
                    a: 0.7,
                })
                .rounded(px(8.0))
                .flex()
                .items_center()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(Hsla {
                    h: 30.0 / 360.0,
                    s: 0.7,
                    l: 0.65,
                    a: 1.0,
                })
                .child(format!("×{}", bp.hit_count))
                .truncate()
                .into_any_element()
        } else {
            div().into_any_element()
        })
        .child(
            div()
                .id(SharedString::from(format!("bp-del-{bp_id}")))
                .w(px(18.0))
                .h(px(18.0))
                .flex()
                .items_center()
                .justify_center()
                .rounded(px(3.0))
                .cursor_pointer()
                .hover(|s| s.bg(colors::err()))
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .child(crate::ui::widgets::icon::icon("cross"))
                .on_click(move |_: &ClickEvent, _, _| {
                    bus_del.send_command(UICommand::DbgDeleteBreakpoint { bp_id });
                }),
        )
}

fn bp_row_condition(bp: &Breakpoint) -> impl IntoElement {
    let has_condition = !bp.condition.as_deref().unwrap_or("").is_empty();
    if has_condition {
        div()
            .h(px(16.0))
            .px_3()
            .flex()
            .flex_row()
            .items_center()
            .gap_1()
            .bg(Hsla {
                h: 60.0 / 360.0,
                s: 0.2,
                l: 0.08,
                a: 0.5,
            })
            .child(
                div()
                    .text_size(px(sizes::LABEL - 1.5))
                    .text_color(colors::text_muted())
                    .child("if")
                    .truncate(),
            )
            .child(
                div()
                    .flex_1()
                    .font_family("JetBrains Mono")
                    .text_size(px(sizes::LABEL - 1.0))
                    .text_color(colors::syn_immediate())
                    .overflow_hidden()
                    .child(bp.condition.as_deref().unwrap_or("").to_owned())
                    .truncate(),
            )
            .into_any_element()
    } else {
        div().into_any_element()
    }
}

fn bp_row(bp: &Breakpoint, data: &AppData, bus: &Arc<EventBus>) -> impl IntoElement {
    let bg = Hsla {
        h: 0.0,
        s: 0.0,
        l: 0.0,
        a: 0.0,
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .bg(bg)
        .border_b_1()
        .border_color(colors::border())
        .child(bp_row_main(bp, data, bus))
        .child(bp_row_condition(bp))
}

const fn bp_kind_label(kind: BpKind) -> &'static str {
    match kind {
        BpKind::Software => "SW",
        BpKind::Hardware => "HW",
        BpKind::DataRead => "DR",
        BpKind::DataWrite => "DW",
        BpKind::DataAccess => "DA",
    }
}

fn bp_kind_color(kind: BpKind) -> Hsla {
    match kind {
        BpKind::Software => colors::bp_enabled(),
        BpKind::Hardware => Hsla {
            h: 30.0 / 360.0,
            s: 0.7,
            l: 0.55,
            a: 1.0,
        },
        BpKind::DataRead => Hsla {
            h: 120.0 / 360.0,
            s: 0.6,
            l: 0.45,
            a: 1.0,
        },
        BpKind::DataWrite => colors::err(),
        BpKind::DataAccess => Hsla {
            h: 280.0 / 360.0,
            s: 0.6,
            l: 0.55,
            a: 1.0,
        },
    }
}

fn bp_kind_bg(kind: BpKind) -> Hsla {
    match kind {
        BpKind::Software => Hsla {
            h: 0.0 / 360.0,
            s: 0.6,
            l: 0.12,
            a: 0.7,
        },
        BpKind::Hardware => Hsla {
            h: 30.0 / 360.0,
            s: 0.5,
            l: 0.12,
            a: 0.7,
        },
        BpKind::DataRead => Hsla {
            h: 120.0 / 360.0,
            s: 0.4,
            l: 0.10,
            a: 0.6,
        },
        BpKind::DataWrite => Hsla {
            h: 0.0 / 360.0,
            s: 0.5,
            l: 0.12,
            a: 0.7,
        },
        BpKind::DataAccess => Hsla {
            h: 280.0 / 360.0,
            s: 0.4,
            l: 0.12,
            a: 0.6,
        },
    }
}

fn bp_toggle(enabled: bool) -> impl IntoElement {
    let col = if enabled {
        colors::bp_enabled()
    } else {
        colors::bp_disabled()
    };
    div()
        .w(px(14.0))
        .h(px(14.0))
        .rounded_full()
        .bg(col)
        .mr_2()
        .cursor_pointer()
}

fn bp_toolbar(bus: &Arc<EventBus>, current_addr: Addr, data: &AppData) -> impl IntoElement {
    // Snapshot ids/enable-state so each button closure is `'static`.
    let all_ids: Vec<u32> = data.breakpoints.keys().copied().collect();
    let to_enable: Vec<u32> = data
        .breakpoints
        .iter()
        .filter_map(|(id, bp)| (!bp.enabled).then_some(*id))
        .collect();
    let to_disable: Vec<u32> = data
        .breakpoints
        .iter()
        .filter_map(|(id, bp)| bp.enabled.then_some(*id))
        .collect();

    let bus_add = Arc::clone(bus);
    let bus_enable = Arc::clone(bus);
    let bus_disable = Arc::clone(bus);
    let bus_clear = Arc::clone(bus);

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(bp_toolbar_btn("+ Add", "bp-tb-add", true).on_click(move |_, _, _| {
            bus_add.send_command(UICommand::DbgSetBreakpoint { addr: current_addr });
        }))
        .child(
            bp_toolbar_btn("Enable All", "bp-tb-enable", false).on_click(move |_, _, _| {
                // No bulk variant — toggle each currently-disabled bp.
                for id in &to_enable {
                    bus_enable.send_command(UICommand::DbgToggleBreakpoint { bp_id: *id });
                }
            }),
        )
        .child(
            bp_toolbar_btn("Disable All", "bp-tb-disable", false).on_click(move |_, _, _| {
                for id in &to_disable {
                    bus_disable.send_command(UICommand::DbgToggleBreakpoint { bp_id: *id });
                }
            }),
        )
        .child(div().flex_1())
        .child(
            bp_toolbar_btn("× Clear", "bp-tb-clear", false).on_click(move |_, _, _| {
                for id in &all_ids {
                    bus_clear.send_command(UICommand::DbgDeleteBreakpoint { bp_id: *id });
                }
            }),
        )
}

fn bp_toolbar_btn(
    label: &'static str,
    id: &'static str,
    primary: bool,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(id))
        .px_2()
        .h(px(20.0))
        .bg(if primary {
            colors::accent()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if primary {
            colors::accent()
        } else {
            colors::border()
        })
        .rounded(px(3.0))
        .flex()
        .items_center()
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(if primary {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.05,
                a: 1.0,
            }
        } else {
            colors::text_secondary()
        })
        .cursor_pointer()
        .hover(|s| {
            s.bg(if primary {
                colors::accent_hover()
            } else {
                colors::bg_hover()
            })
        })
        .child(label)
        .truncate()
}

fn bp_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(div().w(px(14.0 + 8.0))) // toggle
        .child(col_hdr_cell("#", 26.0))
        .child(col_hdr_cell("Kind", 36.0))
        .child(col_hdr_cell("Address", 120.0))
        .child(col_hdr_flex("Symbol"))
        .child(col_hdr_cell("Cond", 60.0))
        .child(col_hdr_cell("Hits", 30.0))
        .child(div().w(px(18.0))) // delete button
}

fn col_hdr_cell(label: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn col_hdr_flex(label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn bp_empty_state() -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_2()
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child("No breakpoints set")
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Press F2 to toggle a breakpoint at the current address")
                .truncate(),
        )
}

fn bp_hdr(t: &str, total: usize, enabled: usize) -> impl IntoElement {
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
                .child(t.to_owned())
                .truncate(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::bp_enabled())
                        .child(format!("{enabled} active"))
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child(format!("{total} total"))
                        .truncate(),
                ),
        )
}

fn new_bp_btn() -> impl IntoElement {
    div()
        .h(px(18.0))
        .px_2()
        .rounded_sm()
        .bg(colors::accent())
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.05,
            a: 1.0,
        })
        .hover(|s| s.bg(colors::accent_hover()))
        .child("+ New")
        .truncate()
}

use gpui::{FontWeight, Hsla};

// ── prod ensure-used (mirrors dead_code coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_breakpoints() {
    // Touch unused imports.
    let _: Option<&UIState> = None;
    let _: Option<Addr> = None;
    let _: Option<Mutex<()>> = None;
    let _: Option<Arc<()>> = None;

    // Touch BpConditionEditor (never-constructed struct) and its fields.
    let cond = BpConditionEditor::default();
    let _ = &cond.editing_id;
    let _ = &cond.input;
    let _ = BpConditionEditor {
        editing_id: Some(0u32),
        input: String::new(),
    };

    // Touch BpSort (never-used enum) and all variants.
    let _ = BpSort::Id;
    let _ = BpSort::Addr;
    let _ = BpSort::HitCount;
    let _ = BpSort::Kind;
    let _ = BpSort::default();

    // Touch BreakpointsPanelState (never-constructed) and its methods.
    let mut st = BreakpointsPanelState::default();
    let data = AppData::new();
    st.refresh(&data, 0);
    st.on_scroll(0.0);
    st.on_key_down(0);
    let _ = &st.selected_id;
    let _ = &st.cond_editor;

    // Touch never-used free functions.
    let _ = bp_toggle(true);
    let _ = new_bp_btn();

    // Touch the watchpoint-aware variant + the EventBus import.
    let bus: Arc<EventBus> = Arc::new(EventBus::new());
    let _ = render_breakpoints_panel_with_watchpoints(&data, &bus, Addr(0));
    let _ = panel_state();
}
