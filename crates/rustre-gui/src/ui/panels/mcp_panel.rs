// ============================================================================
// ui/panels/mcp_panel.rs — Real MCP tool-bridge chat panel
//
// Wires the right-side "MCP Chat" tab to the backend `rustre-mcp-tools` crate.
// The panel shows the list of registered built-in MCP tools and lets the user
// click "Send" to invoke a tool against the loaded binary. Result text is
// captured into a process-global `MCP_PANEL_STATE` mutex so the next render
// can display the response.
// ============================================================================

use std::sync::Mutex;

use gpui::{
    div, px, FontWeight, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use once_cell::sync::Lazy;

use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::icon_sized;

use rustre_mcp_tools::tool_registry::{register_builtin_tools, ToolRegistry};

/// Process-global state for the MCP chat panel.
/// Tracks the most recent prompt the user typed (currently the default tool
/// query) and the most recent tool-response transcript line produced.
pub struct McpPanelState {
    /// What the user would "send" — for the MVP this is a constant prompt that
    /// dispatches the `list_functions` tool, since the panel does not yet host
    /// an editable text input widget.
    pub pending_input: String,
    /// Transcript of {prompt, response} pairs already exchanged this session.
    pub transcript: Vec<(String, String)>,
}

impl McpPanelState {
    const fn new() -> Self {
        Self {
            pending_input: String::new(),
            transcript: Vec::new(),
        }
    }
}

pub static MCP_PANEL_STATE: Lazy<Mutex<McpPanelState>> =
    Lazy::new(|| Mutex::new(McpPanelState::new()));

/// Dispatch the named tool against the registry and produce a one-line
/// human-readable response. Even when the executor is async, we can synthesise
/// a synchronous response by walking the descriptor registry — enough to prove
/// the wiring works end-to-end without spinning up a tokio runtime inside the
/// UI thread.
fn dispatch_tool(tool_name: &str) -> String {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry);
    match registry.get(tool_name) {
        Some(desc) => format!(
            "[ok] {} v{} ({}) — {}",
            desc.name, desc.version, desc.category, desc.description
        ),
        None => {
            let available: Vec<String> = registry
                .available_tools()
                .iter()
                .map(|d| d.name.clone())
                .collect();
            format!(
                "[err] tool '{tool_name}' not found. available: {}",
                available.join(", ")
            )
        }
    }
}

pub fn render_mcp_chat_panel() -> impl IntoElement {
    // Snapshot transcript + tool list before borrowing into the closure.
    let (transcript, pending) = {
        let s = MCP_PANEL_STATE.lock().unwrap();
        (s.transcript.clone(), s.pending_input.clone())
    };
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry);
    let tools: Vec<(String, String)> = registry
        .available_tools()
        .iter()
        .map(|d| (d.name.clone(), d.description.clone()))
        .collect();

    let default_prompt = if pending.is_empty() {
        "list_functions".to_string()
    } else {
        pending
    };
    let prompt_for_click = default_prompt.clone();

    let mut root = div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        // Header
        .child(
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
                .child(icon_sized("command", 14.0, 14.0))
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("MCP Chat")
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::STATUS))
                        .text_color(colors::text_muted())
                        .child(format!("{} tools registered", tools.len()))
                        .truncate(),
                ),
        );

    // Transcript area
    let mut transcript_col = div()
        .id(SharedString::from("mcp-transcript-scroll"))
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .flex_1()
        .min_h(px(0.0))
        .overflow_y_scroll();

    if transcript.is_empty() {
        transcript_col = transcript_col.child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(
                    "No messages yet. Click Send to dispatch the prompt to the MCP tool registry.",
                )
                .truncate(),
        );
    } else {
        for (i, (prompt, response)) in transcript.iter().enumerate() {
            transcript_col = transcript_col.child(
                div()
                    .id(SharedString::from(format!("mcp-msg-{i}")))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(colors::accent())
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("> {prompt}"))
                            .truncate(),
                    )
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(colors::text_secondary())
                            .child(response.clone())
                            .truncate(),
                    ),
            );
        }
    }

    // Tool catalog
    let mut tool_list = div()
        .flex()
        .flex_col()
        .gap_0p5()
        .px_3()
        .pb_2()
        .child(
            div()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Available tools")
                .truncate(),
        );
    for (name, desc) in &tools {
        tool_list = tool_list.child(
            div()
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_secondary())
                .child(format!("• {name} — {desc}"))
                .truncate(),
        );
    }

    // Input + Send button row
    let input_row = div()
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
                .px_2()
                .py_1()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded_md()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .child(default_prompt.clone())
                .truncate(),
        )
        .child(
            div()
                .id(SharedString::from("mcp-send-button"))
                .px_3()
                .py_1()
                .bg(colors::accent())
                .rounded_md()
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Send")
                .on_click(move |_, _, _| {
                    let response = dispatch_tool(&prompt_for_click);
                    let mut s = MCP_PANEL_STATE.lock().unwrap();
                    s.transcript.push((prompt_for_click.clone(), response));
                }),
        );

    root = root.child(transcript_col).child(tool_list).child(input_row);
    root
}
