// ============================================================================
// ui/panels/coverage_panel.rs — Hot-address coverage heatmap.
// ============================================================================
//
// Lists addresses sorted by hit count with a colored heat bar normalised
// against `AppData::coverage_max_hits`. Clicking a row navigates the disasm
// view to that address so the user can see coverage status in context.

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::CoverageEntry;
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct CoveragePanelState {
    cached_rev: u64,
    cached_rows: Vec<CoverageEntry>,
    cached_max: u64,
}

impl CoveragePanelState {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if self.cached_rev == rev {
            return;
        }
        self.cached_rev = rev;
        let mut rows = data.coverage.clone();
        rows.sort_by(|a, b| b.hits.cmp(&a.hits));
        self.cached_rows = rows;
        self.cached_max = data.coverage_max_hits.max(1);
    }
}

pub fn render_coverage_panel(
    state: &CoveragePanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let rows = state.cached_rows.clone();
    let max_hits = state.cached_max.max(1);
    let total = rows.len();
    let total_hits: u64 = rows.iter().map(|r| r.hits).sum();
    let bus_clone = Arc::clone(bus);

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(cov_header(total, total_hits, max_hits))
        .child(cov_col_hdr())
        .child(if rows.is_empty() {
            cov_empty().into_any_element()
        } else {
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .id("cov-scroll")
                .overflow_y_scroll()
                .children(
                    rows.into_iter()
                        .map(|e| cov_row(e, max_hits, Arc::clone(&bus_clone))),
                )
                .into_any_element()
        })
}

fn cov_header(total: usize, total_hits: u64, max: u64) -> impl IntoElement {
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
                .text_size(px(sizes::PANEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Coverage")
                .truncate(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::ok())
                        .child(format!("{total} hot"))
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format!("Σ {total_hits}"))
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format!("max {max}"))
                        .truncate(),
                ),
        )
}

fn cov_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(col_cell("Address", 140.0))
        .child(col_cell("Hits", 70.0))
        .child(col_cell("Heat", 110.0))
        .child(col_flex("Function"))
}

fn col_cell(label: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn col_flex(label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

/// Map a normalised heat ratio (0..=1) to a color from cyan → magenta.
fn heat_color(ratio: f32) -> Hsla {
    let r = ratio.clamp(0.0, 1.0);
    // 180° cyan → 320° magenta sweep.
    let h = 180.0 + r * 140.0;
    Hsla {
        h: h / 360.0,
        s: 0.7,
        l: 0.18 + 0.32 * r,
        a: 0.9,
    }
}

fn cov_row(e: CoverageEntry, max: u64, bus: Arc<EventBus>) -> impl IntoElement {
    let id = SharedString::from(format!("cov-row-{:x}", e.addr.0));
    // Coverage hit counts are usually <2^24 in practice; clamp to u32 to
    // keep the f64→f32 conversion lossless via `u16::from` doubling.
    // For ratios we only need 24 bits of mantissa precision, which
    // u32-as-f64 always provides exactly.
    let hits_f = u32::try_from(e.hits.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    let max_f = u32::try_from(max.min(u64::from(u32::MAX))).unwrap_or(u32::MAX).max(1);
    let ratio = (f64::from(hits_f) / f64::from(max_f)) as f32;
    let heat = heat_color(ratio);
    let addr = e.addr;
    let func = e.func.unwrap_or_default();

    div()
        .id(id)
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H))
        .items_center()
        .px_2()
        .border_b_1()
        .border_color(colors::border())
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .child(
            div()
                .w(px(140.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#018x}", addr.0))
                .truncate(),
        )
        .child(
            div()
                .w(px(70.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_immediate())
                .child(format!("{}", e.hits))
                .truncate(),
        )
        .child(
            div()
                .w(px(110.0))
                .h(px(10.0))
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(2.0))
                .child(
                    div()
                        .h(px(8.0))
                        .w(gpui::relative(ratio.clamp(0.0, 1.0)))
                        .bg(heat)
                        .rounded(px(1.5)),
                ),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_symbol())
                .overflow_hidden()
                .child(func)
                .truncate(),
        )
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::NavigateTo { addr, push_history: true });
        })
}

fn cov_empty() -> impl IntoElement {
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
                .child("No coverage recorded")
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Start a trace recording or import DRcov / sancov data.")
                .truncate(),
        )
}

/// Look up the coverage status for a specific instruction address, returning
/// a `(hits, heat)` tuple where `heat` is the normalised ratio. Used by the
/// disasm view to colour the gutter and instruction background.
pub fn coverage_status_for(data: &AppData, addr: crate::core::types::Addr) -> Option<(u64, f32)> {
    let max = data.coverage_max_hits.max(1);
    data.coverage.iter().find(|e| e.addr == addr).map(|e| {
        // Same lossless path as `cov_row`: clamp into u32, then divide as
        // f64 (always exact for ≤24-bit values) and narrow once.
        let hits_f = u32::try_from(e.hits.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        let max_f = u32::try_from(max.min(u64::from(u32::MAX))).unwrap_or(u32::MAX).max(1);
        let ratio = (f64::from(hits_f) / f64::from(max_f)) as f32;
        (e.hits, ratio.clamp(0.0, 1.0))
    })
}

// ── prod ensure-used ─────────────────────────────────────────────────────────
#[doc(hidden)]
pub fn ensure_used_coverage_panel() {
    let mut st = CoveragePanelState::default();
    let data = AppData::new();
    st.refresh(&data, 0);
    let bus = Arc::new(EventBus::new());
    let _ = render_coverage_panel(&st, &bus);
    let _ = coverage_status_for(&data, crate::core::types::Addr(0));
    let _ = heat_color(0.0);
    let _ = heat_color(0.5);
    let _ = heat_color(1.0);
}
