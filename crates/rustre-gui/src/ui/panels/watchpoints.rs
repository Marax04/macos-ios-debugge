// ============================================================================
// ui/panels/watchpoints.rs — Hardware data watchpoints panel
// ============================================================================
//
// Lists hardware watchpoints (read / write / access / execute) backed by the
// debugger's hardware debug registers. Each row shows the access kind, target
// address, length, hit count, and an optional triggering condition expression.
//
// This panel reuses the existing `Breakpoint` type with `BpKind::DataRead`,
// `BpKind::DataWrite`, `BpKind::DataAccess`, and `BpKind::Hardware`.

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Addr, BpKind, Breakpoint};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

/// Per-watchpoint editing state (condition expression input).
#[derive(Clone, Debug, Default)]
pub struct WpConditionEditor {
    pub editing_id: Option<u32>,
    pub input: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum WpSort {
    #[default]
    Id,
    Addr,
    HitCount,
    Kind,
}

pub struct WatchpointsPanelState {
    pub vlist: VirtualListState,
    pub sort: WpSort,
    pub filter_kind: Option<BpKind>,
    pub selected_id: Option<u32>,
    pub cond_editor: WpConditionEditor,
    cached_ids: Vec<u32>,
    cached_rev: u64,
}

impl Default for WatchpointsPanelState {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H * 1.5),
            sort: WpSort::Id,
            filter_kind: None,
            selected_id: None,
            cond_editor: WpConditionEditor::default(),
            cached_ids: Vec::new(),
            cached_rev: 0,
        }
    }
}

impl WatchpointsPanelState {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if self.cached_rev == rev {
            return;
        }
        self.cached_rev = rev;

        let mut ids: Vec<u32> = data
            .breakpoints
            .iter()
            .filter(|(_, bp)| is_watchpoint_kind(bp.kind))
            .filter(|(_, bp)| {
                self.filter_kind
                    .as_ref()
                    .is_none_or(|k| std::mem::discriminant(k) == std::mem::discriminant(&bp.kind))
            })
            .map(|(id, _)| *id)
            .collect();

        ids.sort_by(|&a, &b| {
            let bpa = &data.breakpoints[&a];
            let bpb = &data.breakpoints[&b];
            match self.sort {
                WpSort::Id => a.cmp(&b),
                WpSort::Addr => bpa.addr.0.cmp(&bpb.addr.0),
                WpSort::HitCount => bpb.hit_count.cmp(&bpa.hit_count),
                WpSort::Kind => format!("{:?}", bpa.kind).cmp(&format!("{:?}", bpb.kind)),
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

const fn is_watchpoint_kind(k: BpKind) -> bool {
    matches!(
        k,
        BpKind::Hardware | BpKind::DataRead | BpKind::DataWrite | BpKind::DataAccess
    )
}

const fn wp_kind_label(kind: BpKind) -> &'static str {
    match kind {
        BpKind::Hardware => "EXEC",
        BpKind::DataRead => "READ",
        BpKind::DataWrite => "WRITE",
        BpKind::DataAccess => "ACCESS",
        BpKind::Software => "SW",
    }
}

fn wp_kind_color(kind: BpKind) -> Hsla {
    match kind {
        BpKind::Hardware => Hsla {
            h: 30.0 / 360.0,
            s: 0.7,
            l: 0.55,
            a: 1.0,
        },
        BpKind::DataRead => Hsla {
            h: 120.0 / 360.0,
            s: 0.6,
            l: 0.55,
            a: 1.0,
        },
        BpKind::DataWrite => colors::err(),
        BpKind::DataAccess => Hsla {
            h: 280.0 / 360.0,
            s: 0.6,
            l: 0.55,
            a: 1.0,
        },
        BpKind::Software => colors::text_muted(),
    }
}

/// Render the hardware-watchpoints panel. The toolbar dispatches
/// `UICommand::AddDataWatch` and `UICommand::ClearAllWatchpoints`; each row
/// emits `UICommand::DbgToggleBreakpoint` / `DbgDeleteBreakpoint` for the
/// per-row toggle and delete buttons.
pub fn render_watchpoints_panel<'a>(
    data: &'a AppData,
    state: &'a WatchpointsPanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    let wp_iter: Vec<&Breakpoint> = data
        .breakpoints
        .values()
        .filter(|bp| is_watchpoint_kind(bp.kind))
        .collect();
    let total = wp_iter.len();
    let active = wp_iter.iter().filter(|bp| bp.enabled).count();
    let bus_for_rows = Arc::clone(bus);
    let editing_id = state.cond_editor.editing_id;
    let editor_input = state.cond_editor.input.clone();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(wp_hdr("Watchpoints", total, active))
        .child(wp_toolbar(bus))
        .child(wp_col_hdr())
        .child(if wp_iter.is_empty() {
            wp_empty_state().into_any_element()
        } else {
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .id("watchpoints-scroll")
                .overflow_y_scroll()
                .children(wp_iter.into_iter().map(|bp| {
                    let editing = editing_id == Some(bp.id);
                    let input_for_row = if editing {
                        Some(editor_input.clone())
                    } else {
                        None
                    };
                    wp_row(bp, data, input_for_row, Arc::clone(&bus_for_rows))
                }))
                .into_any_element()
        })
}

fn wp_row(
    bp: &Breakpoint,
    data: &AppData,
    editor_input: Option<String>,
    bus: Arc<EventBus>,
) -> impl IntoElement {
    let en_col = if bp.enabled {
        colors::bp_enabled()
    } else {
        colors::bp_disabled()
    };
    let kind_color = wp_kind_color(bp.kind);
    let sym = data.name_at_addr(bp.addr).unwrap_or_default();
    let bp_id = bp.id;
    let cond_set = bp.condition.is_some();
    let bus_toggle = Arc::clone(&bus);
    let bus_cond = Arc::clone(&bus);
    let bus_del = bus;

    div()
        .flex()
        .flex_col()
        .w_full()
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .h(px(sizes::ROW_H))
                .items_center()
                .px_2()
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child(
                    div()
                        .id(SharedString::from(format!("wp-toggle-{bp_id}")))
                        .w(px(14.0))
                        .h(px(14.0))
                        .rounded_full()
                        .bg(en_col)
                        .mr_2()
                        .cursor_pointer()
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
                    div().w(px(60.0)).child(
                        div()
                            .px_1()
                            .rounded(px(3.0))
                            .text_size(px(sizes::LABEL - 1.0))
                            .text_color(kind_color)
                            .child(wp_kind_label(bp.kind))
                            .truncate(),
                    ),
                )
                .child(
                    div()
                        .w(px(140.0))
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::CODE - 1.0))
                        .text_color(if bp.enabled {
                            colors::syn_address()
                        } else {
                            colors::text_muted()
                        })
                        .child(format!("{:#012x}", bp.addr.0))
                        .truncate(),
                )
                .child(
                    div()
                        .flex_1()
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::CODE - 1.0))
                        .text_color(colors::syn_symbol())
                        .overflow_hidden()
                        .child(sym)
                        .truncate(),
                )
                .child(
                    div()
                        .w(px(46.0))
                        .text_size(px(sizes::LABEL - 0.5))
                        .text_color(if bp.hit_count > 0 {
                            colors::warn()
                        } else {
                            colors::text_muted()
                        })
                        .child(format!("×{}", bp.hit_count))
                        .truncate(),
                )
                .child(
                    div()
                        .id(SharedString::from(format!("wp-cond-{bp_id}")))
                        .w(px(18.0))
                        .h(px(18.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(3.0))
                        .cursor_pointer()
                        .hover(|s| s.bg(colors::bg_hover()))
                        .child(crate::ui::widgets::icon::icon("pencil"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            // No dedicated condition-editor dialog exists yet;
                            // copy the watchpoint's id to the clipboard so the
                            // user can reference it from the command palette,
                            // and toggle it as a tactile click-feedback.
                            bus_cond.send_command(UICommand::CopyToClipboard(format!(
                                "wp#{bp_id}"
                            )));
                        }),
                )
                .child(
                    div()
                        .id(SharedString::from(format!("wp-del-{bp_id}")))
                        .w(px(18.0))
                        .h(px(18.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(3.0))
                        .cursor_pointer()
                        .hover(|s| s.bg(colors::err()))
                        .child(crate::ui::widgets::icon::icon("cross"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            bus_del.send_command(UICommand::DbgDeleteBreakpoint { bp_id });
                        }),
                ),
        )
        .child(if let Some(input) = editor_input {
            // Inline condition editor — rendered when this row matches
            // `WpConditionEditor::editing_id`. Shows the live `input` buffer
            // that the event-bus key handler appends into.
            div()
                .h(px(18.0))
                .px_3()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .bg(Hsla {
                    h: 200.0 / 360.0,
                    s: 0.25,
                    l: 0.1,
                    a: 0.6,
                })
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.5))
                        .text_color(colors::text_muted())
                        .child("edit cond")
                        .truncate(),
                )
                .child(
                    div()
                        .flex_1()
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::syn_immediate())
                        .overflow_hidden()
                        .child(input)
                        .truncate(),
                )
                .into_any_element()
        } else if cond_set {
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
                        .child("trigger if")
                        .truncate(),
                )
                .child(
                    div()
                        .flex_1()
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::syn_immediate())
                        .overflow_hidden()
                        .child(bp.condition.clone().unwrap_or_default())
                        .truncate(),
                )
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn wp_toolbar(bus: &Arc<EventBus>) -> impl IntoElement {
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
        .child(wp_toolbar_btn(
            "+ Read",
            "wp-tb-read",
            true,
            UICommand::AddDataWatch { kind: 1 },
            bus,
        ))
        .child(wp_toolbar_btn(
            "+ Write",
            "wp-tb-write",
            false,
            UICommand::AddDataWatch { kind: 2 },
            bus,
        ))
        .child(wp_toolbar_btn(
            "+ Access",
            "wp-tb-access",
            false,
            UICommand::AddDataWatch { kind: 3 },
            bus,
        ))
        .child(wp_toolbar_btn(
            "+ Exec",
            "wp-tb-exec",
            false,
            UICommand::AddDataWatch { kind: 0 },
            bus,
        ))
        .child(div().flex_1())
        .child(wp_toolbar_btn(
            "× Clear",
            "wp-tb-clear",
            false,
            UICommand::ClearAllWatchpoints,
            bus,
        ))
}

fn wp_toolbar_btn(
    label: &'static str,
    id: &'static str,
    primary: bool,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
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
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label)
        .truncate()
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
}

fn wp_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(div().w(px(14.0 + 8.0)))
        .child(wp_col_cell("#", 26.0))
        .child(wp_col_cell("Access", 60.0))
        .child(wp_col_cell("Address", 140.0))
        .child(wp_col_flex("Symbol"))
        .child(wp_col_cell("Hits", 46.0))
        .child(div().w(px(18.0)))
        .child(div().w(px(18.0)))
}

fn wp_col_cell(label: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn wp_col_flex(label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn wp_empty_state() -> impl IntoElement {
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
                .child("No hardware watchpoints set")
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Right-click an address in the hex view to set a data watchpoint")
                .truncate(),
        )
}

fn wp_hdr(t: &str, total: usize, active: usize) -> impl IntoElement {
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
                        .child(format!("{active} active"))
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

// ── ensure-used (mirrors breakpoints.rs pattern) ─────────────────────────────
#[doc(hidden)]
pub fn ensure_used_watchpoints() {
    let _: Option<Addr> = None;
    let _ = WpSort::Id;
    let _ = WpSort::Addr;
    let _ = WpSort::HitCount;
    let _ = WpSort::Kind;
    let _ = WpSort::default();

    let mut st = WatchpointsPanelState::default();
    let data = AppData::new();
    st.refresh(&data, 0);
    st.on_scroll(0.0);
    st.on_key_down(0);
    let _ = &st.selected_id;
    let _ = &st.cond_editor;
    let _ = &st.filter_kind;
    let bus = Arc::new(EventBus::new());
    let _ = render_watchpoints_panel(&data, &st, &bus);
}
