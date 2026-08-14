// ============================================================================
// ui/panels/stack.rs — Call-stack panel with frame details, top-frame
// indicator, module badges, library-frame dimming, and LIVE/IDLE header.
// ============================================================================
use crate::core::app_state::AppData;
use crate::core::types::StackFrame;
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled,
};

// ── Public entry point ────────────────────────────────────────────────────────

pub fn render_stack_panel(data: &AppData) -> impl IntoElement + '_ {
    let frames = &data.stack_frames;
    let is_attached = data.dbg_attached;
    let replay = !data.replay_stack.is_empty();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(stack_panel_header(is_attached, frames.len()))
        .child(if replay {
            replay_banner(data).into_any_element()
        } else {
            div().into_any_element()
        })
        .child(col_headers())
        .child(
            div()
                .id("stack-scroll")
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .overflow_y_scroll()
                .children(
                    frames
                        .iter()
                        .enumerate()
                        .map(|(idx, f)| frame_row(f, idx == 0)),
                )
                .children(data.replay_stack.iter().map(replay_frame_row))
                .child(if frames.is_empty() && data.replay_stack.is_empty() {
                    empty_state(is_attached).into_any_element()
                } else {
                    div().into_any_element()
                }),
        )
}

/// Banner shown above the call-stack list during trace replay. Displays the
/// current trace cursor (`seq` / `tid`) and the number of reconstructed
/// frames so the user knows the stack reflects historical state, not live
/// debugger state.
fn replay_banner(data: &AppData) -> impl IntoElement {
    let seq = data.trace_cursor.seq;
    let tid = data.trace_cursor.thread;
    let frames = data.replay_stack.len();
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(20.0))
        .px_2()
        .bg(Hsla { h: 0.58, s: 0.5, l: 0.10, a: 0.5 })
        .border_b_1()
        .border_color(colors::border_accent())
        .child(
            div()
                .px(px(5.0))
                .h(px(14.0))
                .flex()
                .items_center()
                .rounded_sm()
                .bg(colors::accent())
                .text_size(px(8.5))
                .text_color(Hsla { h: 0.0, s: 0.0, l: 0.06, a: 1.0 })
                .font_weight(FontWeight::BOLD)
                .child("REPLAY")
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_secondary())
                .font_family("JetBrains Mono")
                .child(format!("seq {seq}  tid {tid}  {frames} frames"))
                .truncate(),
        )
}

/// Render a single reconstructed call-stack frame from a trace replay. Uses
/// the same column layout as `frame_row` but never marks a frame as TOP and
/// shows the return address as an extra detail column.
fn replay_frame_row(f: &crate::core::types::ReplayFrame) -> impl IntoElement {
    let func = f
        .func
        .clone()
        .unwrap_or_else(|| format!("sub_{:08x}", f.addr.0));
    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 2.0))
        .items_center()
        .px_2()
        .bg(Hsla { h: 0.58, s: 0.3, l: 0.08, a: 0.3 })
        .border_b_1()
        .border_color(Hsla { h: 0.0, s: 0.0, l: 0.12, a: 0.4 })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(12.0))
                .h(px(8.0))
                .child(
                    div()
                        .w(px(6.0))
                        .h(px(6.0))
                        .rounded_full()
                        .bg(colors::accent()),
                ),
        )
        .child(frame_index_cell(f.index, false))
        .child(
            div()
                .w(px(130.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#016x}", f.return_addr.0))
                .truncate(),
        )
        .child(
            div()
                .w(px(110.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::text_secondary())
                .child(format!("{:#016x}", f.sp))
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_symbol())
                .child(func)
                .truncate(),
        )
        .child(
            div()
                .w(px(90.0))
                .text_size(px(8.5))
                .text_color(colors::accent_blue())
                .child(format!("{:#x}", f.addr.0))
                .truncate(),
        )
}

// ── Panel header ──────────────────────────────────────────────────────────────

fn stack_panel_header(is_attached: bool, count: usize) -> impl IntoElement {
    let status_bg = if is_attached {
        colors::ok()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.3,
            a: 1.0,
        }
    };
    let status_text = if is_attached { "LIVE" } else { "IDLE" };

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
                        .child("Call Stack")
                        .truncate(),
                )
                .child(
                    div()
                        .px(px(5.0))
                        .h(px(14.0))
                        .flex()
                        .items_center()
                        .rounded_sm()
                        .bg(status_bg)
                        .text_size(px(8.5))
                        .text_color(Hsla {
                            h: 0.0,
                            s: 0.0,
                            l: 0.06,
                            a: 1.0,
                        })
                        .font_weight(FontWeight::BOLD)
                        .child(status_text)
                        .truncate(),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(format!("{count} frames"))
                .truncate(),
        )
}

// ── Column headers ─────────────────────────────────────────────────────────────

fn col_headers() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(18.0))
        .items_center()
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        // Indicator column
        .child(div().w(px(12.0)))
        // Frame #
        .child(
            div()
                .w(px(28.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("#")
                .truncate(),
        )
        // Address
        .child(
            div()
                .w(px(130.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Return Address")
                .truncate(),
        )
        // SP
        .child(
            div()
                .w(px(110.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Stack Pointer")
                .truncate(),
        )
        // Function
        .child(
            div()
                .flex_1()
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Function")
                .truncate(),
        )
        // Module
        .child(
            div()
                .w(px(90.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Module")
                .truncate(),
        )
}

// ── Frame row ─────────────────────────────────────────────────────────────────

fn frame_indicator_dot(is_top: bool) -> impl IntoElement {
    div()
        .w(px(8.0))
        .h(px(8.0))
        .rounded_full()
        .mr(px(4.0))
        .bg(if is_top {
            colors::syn_address()
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .flex_shrink_0()
}

fn frame_index_cell(index: u32, is_top: bool) -> impl IntoElement {
    div()
        .w(px(28.0))
        .text_size(px(sizes::LABEL))
        .text_color(if is_top {
            colors::text_primary()
        } else {
            colors::text_muted()
        })
        .font_weight(if is_top {
            FontWeight::SEMIBOLD
        } else {
            FontWeight::NORMAL
        })
        .child(format!("#{index}"))
        .truncate()
}

fn frame_func_cell(func: &str, func_color: Hsla, is_top: bool) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .child(
            div()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(func_color)
                .child(func.to_owned())
                .truncate(),
        )
        .child(if is_top {
            div()
                .px(px(4.0))
                .h(px(12.0))
                .flex()
                .items_center()
                .rounded_sm()
                .bg(colors::syn_address())
                .text_size(px(8.0))
                .text_color(Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.05,
                    a: 1.0,
                })
                .font_weight(FontWeight::BOLD)
                .child("TOP")
                .truncate()
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn frame_module_cell(module_short: &str) -> impl IntoElement {
    div()
        .w(px(90.0))
        .flex()
        .items_center()
        .child(if module_short.is_empty() {
            div().into_any_element()
        } else {
            div()
                .px(px(4.0))
                .h(px(14.0))
                .flex()
                .items_center()
                .rounded_sm()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .child(module_short.to_owned())
                .truncate()
                .into_any_element()
        })
}

fn frame_row(f: &StackFrame, is_top: bool) -> impl IntoElement {
    let func_fallback = format!("sub_{:08x}", f.addr.0);
    let func = f.func.as_deref().unwrap_or(&func_fallback);
    let module_raw = f.module.as_deref().unwrap_or("");
    let module_short = trim_module_path(module_raw);

    // Library frames (no function name resolved) are dimmed
    let is_lib = f.func.is_none();
    let func_color = if is_top {
        colors::syn_address()
    } else if is_lib {
        colors::text_muted()
    } else {
        colors::syn_symbol()
    };

    let row_bg = if is_top {
        Hsla {
            h: 0.58,
            s: 0.5,
            l: 0.15,
            a: 0.4,
        }
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 2.0))
        .items_center()
        .px_2()
        .bg(row_bg)
        .border_b_1()
        .border_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.12,
            a: 0.4,
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(frame_indicator_dot(is_top))
        .child(frame_index_cell(f.index, is_top))
        // Return address
        .child(
            div()
                .w(px(130.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#016x}", f.addr.0))
                .truncate(),
        )
        // Stack pointer
        .child(
            div()
                .w(px(110.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::text_secondary())
                .child(format!("{:#016x}", f.sp))
                .truncate(),
        )
        .child(frame_func_cell(func, func_color, is_top))
        .child(frame_module_cell(module_short))
}

// ── Empty state ───────────────────────────────────────────────────────────────

fn empty_state(is_attached: bool) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .w_full()
        .pt(px(24.0))
        .gap(px(6.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_muted())
                .child(if is_attached {
                    "Process is running"
                } else {
                    "No active debug session"
                })
                .truncate(),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .child(if is_attached {
                    "Pause execution to view the call stack."
                } else {
                    "Attach or launch a process to see the call stack."
                })
                .truncate(),
        )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return only the final path component (filename) of a module path.
fn trim_module_path(path: &str) -> &str {
    if path.is_empty() {
        return path;
    }
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}
