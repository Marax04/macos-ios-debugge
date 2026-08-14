// ============================================================================
// ui/panels/rustre_stubs.rs — Visual-only stub panels for upcoming RE features
//
// These render a Zyphora-styled "Coming soon" placeholder for every advanced
// reverse-engineering capability listed in the RustRE spec (TTD timeline,
// MCP chat, YARA rule manager, fuzzing dashboard, sandbox console, AI
// annotations, coverage heatmap, signature matches, taint graph, symbolic
// execution view, ROP gadget viewer, …). No real implementation — only the
// chrome, so the menu/tab entries that wire these in have something concrete
// to display.
// ============================================================================

use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::icon_sized;
use gpui::{
    div, px, FontWeight, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};

/// Compact one-line body row: icon + title + dim blurb on a single row.
/// Designed to remain readable inside the short bottom panel and inside
/// narrow side panels alike — no fixed heights, everything flex-shrinkable.
fn stub_body(
    panel_id: &'static str,
    title: &'static str,
    blurb: &'static str,
    icon_name: &'static str,
) -> impl IntoElement {
    let scroll_id = SharedString::from(format!("{panel_id}-stub-scroll"));
    div()
        .id(scroll_id)
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .overflow_y_scroll()
        .child(
            // Top hero row — icon + title side by side. Wraps when narrow.
            div()
                .flex()
                .flex_row()
                .flex_wrap()
                .items_center()
                .gap_3()
                .p_3()
                .child(
                    div()
                        .w(px(40.0))
                        .h(px(40.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .flex_none()
                        .bg(colors::bg_elevated())
                        .border_1()
                        .border_color(colors::border_accent())
                        .rounded_md()
                        .child(icon_sized(icon_name, 22.0, 22.0)),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w(px(120.0))
                        .flex()
                        .flex_col()
                        .gap_0p5()
                        .child(
                            div()
                                .text_size(px(sizes::HEADING))
                                .text_color(colors::accent())
                                .font_weight(FontWeight::BOLD)
                                .child(title)
                                .truncate(),
                        )
                        .child(
                            div()
                                .text_size(px(sizes::STATUS))
                                .text_color(colors::text_muted())
                                .child("UI placeholder - implementation upcoming")
                                .truncate(),
                        ),
                ),
        )
        .child(
            // Description: shrinks/wraps naturally, full width, with padding.
            div()
                .px_3()
                .pb_3()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(blurb),
        )
}

fn stub_panel(
    panel_id: &'static str,
    title: &'static str,
    blurb: &'static str,
    icon_name: &'static str,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(
            // Header
            div()
                .flex()
                .flex_row()
                .items_center()
                .h(px(26.0))
                .px_3()
                .flex_none()
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(title)
                        .truncate(),
                ),
        )
        .child(
            div()
                .flex_1()
                .min_h(px(0.0))
                .child(stub_body(panel_id, title, blurb, icon_name)),
        )
}

// ── Bottom-row panels ───────────────────────────────────────────────────────

pub fn render_ttd_timeline_panel() -> impl IntoElement {
    stub_panel(
        "ttd-timeline",
        "TTD Timeline",
        "Time-travel debugging trace navigator. Scrub forward/backward through every recorded instruction with reverse-step support.",
        "stopwatch",
    )
}

pub fn render_sandbox_output_panel() -> impl IntoElement {
    stub_panel(
        "sandbox-output",
        "Sandbox Output",
        "Detonation telemetry from the in-process sandbox: API calls, dropped files, network connections, and registry writes.",
        "alembic",
    )
}

pub fn render_coverage_heatmap_panel() -> impl IntoElement {
    stub_panel(
        "coverage-heatmap",
        "Coverage Heatmap",
        "Per-block execution counts overlaid on the current binary. Imports DRcov / sancov / fuzzing corpora to visualise reach.",
        "chart_bar",
    )
}

// ── Left-side panels ────────────────────────────────────────────────────────

pub fn render_yara_rules_panel() -> impl IntoElement {
    stub_panel(
        "yara-rules",
        "YARA Rules",
        "Manage YARA rule sets, scan the current binary, and explore matches with offset and snippet context.",
        "puzzle",
    )
}

pub fn render_signature_matches_panel() -> impl IntoElement {
    stub_panel(
        "signature-matches",
        "Signature Matches",
        "FLIRT / SigKit / IDB signature hits with confidence scores. Apply matched names and prototypes in bulk.",
        "search_alt",
    )
}

// ── Right-side panels ──────────────────────────────────────────────────────
//
// `render_mcp_chat_panel` and `render_ai_annotations_panel` previously lived
// here as placeholder stubs. The real implementations now live in
// `super::mcp_panel` and `super::ai_panel`. The ai-annotations re-export
// is no longer needed (every caller imports directly from `super::ai_panel`);
// keep only the mcp re-export which the legacy panel-mod tree still hits.
pub use super::mcp_panel::render_mcp_chat_panel;

#[doc(hidden)]
pub fn ensure_used_rustre_stubs() {
    let _ = render_ttd_timeline_panel().into_any_element();
    let _ = render_sandbox_output_panel().into_any_element();
    let _ = render_coverage_heatmap_panel().into_any_element();
    let _ = render_yara_rules_panel().into_any_element();
    let _ = render_signature_matches_panel().into_any_element();
    let _ = render_mcp_chat_panel().into_any_element();
    // AI panel needs a UIState; constructing one just for an ensure-used
    // call would mean reproducing all UIState defaults here. Skip — the real
    // call site in `ui/app.rs` keeps the symbol live.
}
