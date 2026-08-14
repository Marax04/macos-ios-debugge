// ============================================================================
// ui/panels/ai_panel.rs — Real AI annotations panel
//
// Wires the right-side "AI Annotations" tab to the backend `rustre-agent-llm`
// crate. The panel displays existing annotations keyed by the current address
// and exposes an "Ask AI" button that synthesises a short auto-prompt for the
// current function and records the resulting (prompt, response) annotation.
//
// The LLM trait in `rustre-agent-llm` is async; rather than block the UI
// thread on a real network round-trip, the MVP build uses an in-process stub
// response derived from the prompt itself. The pathway from button -> backend
// prompt -> annotation is fully wired; swapping the stub for a real
// `LlmClient::complete` call is a one-line change.
// ============================================================================

use std::sync::Mutex;

use gpui::{
    div, px, FontWeight, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use once_cell::sync::Lazy;

use crate::core::app_state::UIState;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::icon_sized;

use rustre_agent_llm::{CompletionOptions, Message};

/// One AI-generated annotation, keyed by the address it was produced for.
#[derive(Clone, Debug)]
pub struct AiAnnotation {
    pub addr: u64,
    pub prompt: String,
    pub response: String,
}

pub struct AiPanelState {
    pub annotations: Vec<AiAnnotation>,
}

impl AiPanelState {
    const fn new() -> Self {
        Self {
            annotations: Vec::new(),
        }
    }
}

pub static AI_PANEL_STATE: Lazy<Mutex<AiPanelState>> =
    Lazy::new(|| Mutex::new(AiPanelState::new()));

/// Build the auto-prompt for the address currently focused in the UI.
fn build_auto_prompt(addr: u64) -> Vec<Message> {
    vec![
        Message::system(
            "You are a reverse-engineering assistant. Explain the function at the given address in this binary in one short paragraph.",
        ),
        Message::user(format!("Explain function at {addr:#018x} in this binary.")),
    ]
}

/// Synchronous placeholder response. The async `LlmClient::complete` path is
/// available via `rustre_agent_llm::LlmClient`; this MVP synthesises a
/// deterministic answer so the wiring can be exercised without configuring a
/// provider/API key.
fn synth_response(messages: &[Message], opts: &CompletionOptions) -> String {
    let user_msg = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("");
    format!(
        "(stub LLM, max_tokens={}, temp={:.1}) Auto-summary for: {user_msg}",
        opts.max_tokens, opts.temperature
    )
}

pub fn render_ai_annotations_panel(ui: &UIState) -> impl IntoElement {
    let current_addr = ui.current_addr;
    let addr_u64 = current_addr.0;

    let annotations = AI_PANEL_STATE.lock().unwrap().annotations.clone();
    let for_current: Vec<AiAnnotation> = annotations
        .iter()
        .filter(|a| a.addr == addr_u64)
        .cloned()
        .collect();

    let mut root = div()
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
                .gap_2()
                .h(px(26.0))
                .px_3()
                .flex_none()
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .child(icon_sized("memo", 14.0, 14.0))
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("AI Annotations")
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::STATUS))
                        .text_color(colors::text_muted())
                        .child(format!("{addr_u64:#018x}"))
                        .truncate(),
                ),
        );

    // Annotations list for the current address.
    let mut list = div()
        .id(SharedString::from("ai-annotations-scroll"))
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .flex_1()
        .min_h(px(0.0))
        .overflow_y_scroll();

    if for_current.is_empty() {
        list = list.child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(format!(
                    "No annotations yet for {addr_u64:#018x}. Click 'Ask AI' to generate one."
                ))
                .truncate(),
        );
    } else {
        for (i, ann) in for_current.iter().enumerate() {
            list = list.child(
                div()
                    .id(SharedString::from(format!("ai-ann-{i}")))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(colors::accent())
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("Q: {}", ann.prompt))
                            .truncate(),
                    )
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(colors::text_secondary())
                            .child(format!("A: {}", ann.response))
                            .truncate(),
                    ),
            );
        }
    }

    // "Ask AI" button.
    let button_row = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .pb_3()
        .pt_2()
        .border_t_1()
        .border_color(colors::border())
        .flex_none()
        .child(
            div()
                .flex_1()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .child(format!(
                    "Prompt: Explain function at {addr_u64:#018x} in this binary."
                ))
                .truncate(),
        )
        .child(
            div()
                .id(SharedString::from("ai-ask-button"))
                .px_3()
                .py_1()
                .bg(colors::accent())
                .rounded_md()
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Ask AI")
                .on_click(move |_, _, _| {
                    let messages = build_auto_prompt(addr_u64);
                    let opts = CompletionOptions::default();
                    let response = synth_response(&messages, &opts);
                    let prompt_text = messages
                        .iter()
                        .rev()
                        .find(|m| m.role == "user")
                        .map(|m| m.content.clone())
                        .unwrap_or_default();
                    let mut s = AI_PANEL_STATE.lock().unwrap();
                    s.annotations.push(AiAnnotation {
                        addr: addr_u64,
                        prompt: prompt_text,
                        response,
                    });
                }),
        );

    root = root.child(list).child(button_row);
    root
}
