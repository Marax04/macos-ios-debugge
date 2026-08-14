// ============================================================================
// ui/panels/trace_panel.rs — Trace recording + playback control panel.
// ============================================================================
//
// Shows the current `TraceState` (Idle / Recording / Replaying / …), exposes
// a Start/Stop record button, Play/Pause and frame-by-frame Step controls,
// and renders a horizontal progress bar covering the recorded sequence range
// so the user can see how far the playback cursor has advanced.

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::TraceState;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::icon_colored;
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

/// Local state owned by the Trace panel (sort, filters, last cursor seen).
#[derive(Clone, Debug, Default)]
pub struct TracePanelState {
    pub last_cursor_seq: u64,
    pub last_total: u64,
    cached_rev: u64,
}

impl TracePanelState {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if self.cached_rev == rev {
            return;
        }
        self.cached_rev = rev;
        self.last_cursor_seq = data.trace_cursor.seq;
        self.last_total = data.trace_total;
    }
}

/// Render the trace control panel.
pub fn render_trace_panel(data: &AppData, bus: &Arc<EventBus>) -> impl IntoElement {
    let state = data.trace_state;
    let cur = data.trace_cursor.seq;
    let total = data.trace_total;
    let pct = if total == 0 {
        0.0_f32
    } else {
        // Trace seq numbers are u64 but only the ratio matters for the
        // progress bar. u32 has plenty of headroom for any plausible
        // recording length; clamp + f64 division stays lossless to the
        // 24-bit f32 mantissa we narrow to.
        let cur_f = u32::try_from(cur.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        let tot_f = u32::try_from(total.min(u64::from(u32::MAX))).unwrap_or(u32::MAX).max(1);
        ((f64::from(cur_f) / f64::from(tot_f)) as f32).clamp(0.0, 1.0)
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(trace_header(state, cur, total))
        .child(trace_toolbar(state, bus))
        .child(trace_progress(pct, cur, total))
        .child(trace_status_row(data, state))
}

fn state_label(s: TraceState) -> (&'static str, Hsla) {
    match s {
        TraceState::Idle => ("IDLE", colors::text_muted()),
        TraceState::Recording => ("REC", colors::err()),
        TraceState::Stopped => ("STOP", colors::text_secondary()),
        TraceState::Replaying => ("PLAY", colors::ok()),
        TraceState::Paused => ("PAUSE", colors::warn()),
    }
}

fn trace_header(state: TraceState, cur: u64, total: u64) -> impl IntoElement {
    let (label, col) = state_label(state);
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(28.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Trace")
                        .truncate(),
                )
                .child(
                    div()
                        .px(px(5.0))
                        .h(px(14.0))
                        .flex()
                        .items_center()
                        .rounded_sm()
                        .bg(col)
                        .text_size(px(8.5))
                        .text_color(Hsla { h: 0.0, s: 0.0, l: 0.06, a: 1.0 })
                        .font_weight(FontWeight::BOLD)
                        .child(label)
                        .truncate(),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .font_family("JetBrains Mono")
                .child(format!("seq {cur} / {total}"))
                .truncate(),
        )
}

fn trace_tool_btn(
    label: &'static str,
    icon_name: &'static str,
    color: Hsla,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
    let id = SharedString::from(format!("trace-tb-{label}"));
    div()
        .id(id)
        .px_2()
        .h(px(22.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(3.0))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .child(icon_colored(icon_name, color))
        .child(
            div()
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_secondary())
                .child(label)
                .truncate(),
        )
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
}

fn trace_toolbar(state: TraceState, bus: &Arc<EventBus>) -> impl IntoElement {
    let (rec_label, rec_icon, rec_color, rec_cmd) = if matches!(state, TraceState::Recording) {
        ("Stop", "pause", colors::err(), UICommand::TraceStopRecording)
    } else {
        ("Record", "circle_filled", colors::err(), UICommand::TraceStartRecording)
    };
    let (play_label, play_icon, play_cmd) = if matches!(state, TraceState::Replaying) {
        ("Pause", "pause", UICommand::TracePause)
    } else {
        ("Play", "play", UICommand::TracePlay)
    };

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .h(px(28.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(trace_tool_btn(rec_label, rec_icon, rec_color, rec_cmd, bus))
        .child(trace_tool_btn(play_label, play_icon, colors::ok(), play_cmd, bus))
        .child(trace_tool_btn(
            "Prev",
            "arrow-left",
            colors::accent_blue(),
            UICommand::TraceStepBackward,
            bus,
        ))
        .child(trace_tool_btn(
            "Next",
            "arrow-right",
            colors::accent_blue(),
            UICommand::TraceStepForward,
            bus,
        ))
        .child(trace_tool_btn(
            "First",
            "skip-forward",
            colors::accent(),
            UICommand::TraceJumpToSeq { seq: 0 },
            bus,
        ))
}

fn trace_progress(pct: f32, cur: u64, total: u64) -> impl IntoElement {
    let fill_w_pct = (pct * 100.0).clamp(0.0, 100.0);
    div()
        .flex()
        .flex_col()
        .w_full()
        .px_3()
        .py_2()
        .gap_1()
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 0.5))
                        .text_color(colors::text_muted())
                        .child("Playback")
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 0.5))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format!("{fill_w_pct:>5.1}%"))
                        .truncate(),
                ),
        )
        .child(
            div()
                .w_full()
                .h(px(8.0))
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(4.0))
                .child(
                    div()
                        .h(px(6.0))
                        .w(gpui::relative(pct))
                        .bg(colors::accent())
                        .rounded(px(3.0)),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format!("{cur}"))
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format!("{total}"))
                        .truncate(),
                ),
        )
}

fn trace_status_row(data: &AppData, state: TraceState) -> impl IntoElement {
    let events = data.trace_events.len();
    let thread = data.trace_cursor.thread;
    let frames = data.replay_stack.len();
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_3()
        .h(px(22.0))
        .px_3()
        .bg(colors::bg_surface())
        .border_t_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .child(format!("{events} events"))
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .font_family("JetBrains Mono")
                .child(format!("tid {thread}"))
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .child(format!("{frames} frames"))
                .truncate(),
        )
        .child(div().flex_1())
        .child({
            let (label, col) = state_label(state);
            div()
                .text_size(px(sizes::STATUS))
                .text_color(col)
                .child(label)
                .truncate()
        })
}

// ── prod ensure-used ─────────────────────────────────────────────────────────
#[doc(hidden)]
pub fn ensure_used_trace_panel() {
    let mut st = TracePanelState::default();
    let data = AppData::new();
    st.refresh(&data, 0);
    let _ = st.last_cursor_seq;
    let _ = st.last_total;
    let bus = Arc::new(EventBus::new());
    let _ = render_trace_panel(&data, &bus);
    let _ = state_label(TraceState::Idle);
    let _ = state_label(TraceState::Recording);
    let _ = state_label(TraceState::Stopped);
    let _ = state_label(TraceState::Replaying);
    let _ = state_label(TraceState::Paused);
}
