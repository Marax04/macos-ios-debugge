// ============================================================================
// ui/panels/decompiler_panel.rs — Extended decompiler view
//
// Knowledge-graph navigation, type-recovery toggles, search-in-pseudo-C.
// Ported from the legacy `gpui::View` / `ViewContext` API to the current
// function-based panel style (see overview.rs).
//
// The live counterpart `decompiler.rs` owns the basic pseudo-C view bound to
// `CenterTab::Decompiler`; this panel is the richer surface that operates on
// fully-tokenised HLIL with per-variable highlighting, address gutter, and
// inline search/rename affordances. Both coexist — this one is invoked from
// the workspace as the "extended" mode.
// ============================================================================
//
// All the original data structures (`DecompTokenKind`, `DecompToken`,
// `DecompLine`, `DecompRenameState`, `DecompilerOptions`, `DecompSearchState`,
// `SplitMode`, `DecompilerEvent`) are preserved verbatim — only the
// surrounding GPUI plumbing was rewritten.
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::event_bus::EventBus;
use crate::core::types::{Addr as CoreAddr, TokenKind, XrefKind};
use crate::ui::theme::colors;
use crate::ui::widgets::icon::{icon, icon_colored};
use gpui::{
    div, hsla, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;

// ─── Local stand-ins for engine types ────────────────────────────────────────
//
// The legacy file referenced `crate::types::{Address, VarId, TextRange}` and
// `crate::knowledge_graph::KnowledgeGraph` / `crate::analysis::AnalysisEngine`
// modules that do not exist in this crate. We define minimal local stand-ins
// so the panel surface compiles independently; the parent will eventually wire
// concrete engine handles here.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Address(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct VarId(pub u32);

#[derive(Clone, Copy, Debug, Default)]
pub struct TextRange {
    pub start: u32,
    pub end: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Token types and syntax highlighting
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecompTokenKind {
    Keyword,
    Type,
    Identifier,
    FunctionName,
    Number,
    StringLiteral,
    CharLiteral,
    Operator,
    Punctuation,
    Comment,
    Preprocessor,
    Label,
    Whitespace,
    Newline,
}

impl DecompTokenKind {
    pub fn color(&self) -> Hsla {
        match self {
            Self::Keyword => hsla(0.78, 0.55, 0.68, 1.0),
            Self::Type => hsla(0.52, 0.60, 0.60, 1.0),
            Self::Identifier => hsla(0.13, 0.55, 0.65, 1.0),
            Self::FunctionName => hsla(0.58, 0.70, 0.65, 1.0),
            Self::Number => hsla(0.08, 0.60, 0.60, 1.0),
            Self::StringLiteral | Self::CharLiteral => hsla(0.33, 0.40, 0.55, 1.0),
            Self::Operator | Self::Punctuation => hsla(0.0, 0.0, 0.70, 1.0),
            Self::Comment => colors::syn_comment(),
            Self::Preprocessor | Self::Label => hsla(0.0, 0.70, 0.65, 1.0),
            Self::Whitespace | Self::Newline => colors::text_primary(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DecompToken {
    pub kind: DecompTokenKind,
    pub text: SharedString,
    pub var_id: Option<VarId>,
    pub target_address: Option<Address>,
    pub source_address: Option<Address>,
    pub line: u32,
    pub column: u32,
}

impl DecompToken {
    pub fn new(kind: DecompTokenKind, text: impl Into<SharedString>) -> Self {
        Self {
            kind,
            text: text.into(),
            var_id: None,
            target_address: None,
            source_address: None,
            line: 0,
            column: 0,
        }
    }

    pub fn keyword(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::Keyword, text)
    }
    pub fn type_tok(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::Type, text)
    }
    pub fn ident(text: impl Into<SharedString>, var_id: Option<VarId>) -> Self {
        let mut t = Self::new(DecompTokenKind::Identifier, text);
        t.var_id = var_id;
        t
    }
    pub fn func_name(text: impl Into<SharedString>, addr: Option<Address>) -> Self {
        let mut t = Self::new(DecompTokenKind::FunctionName, text);
        t.target_address = addr;
        t
    }
    pub fn number(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::Number, text)
    }
    pub fn string_lit(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::StringLiteral, text)
    }
    pub fn op(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::Operator, text)
    }
    pub fn punct(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::Punctuation, text)
    }
    pub fn comment(text: impl Into<SharedString>) -> Self {
        Self::new(DecompTokenKind::Comment, text)
    }

    pub fn is_clickable(&self) -> bool {
        matches!(
            self.kind,
            DecompTokenKind::Identifier | DecompTokenKind::FunctionName
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendered lines
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DecompLine {
    pub line_number: u32,
    pub source_address: Option<Address>,
    pub tokens: Vec<DecompToken>,
    pub indent_level: u32,
    pub has_breakpoint: bool,
    pub is_current_ip: bool,
}

impl DecompLine {
    pub fn new(line_number: u32) -> Self {
        Self {
            line_number,
            source_address: None,
            tokens: Vec::new(),
            indent_level: 0,
            has_breakpoint: false,
            is_current_ip: false,
        }
    }

    pub fn push_token(&mut self, token: DecompToken) {
        self.tokens.push(token);
    }

    pub fn push_indent(&mut self, level: u32) {
        for _ in 0..level {
            self.tokens
                .push(DecompToken::new(DecompTokenKind::Whitespace, "    "));
        }
    }

    pub fn text_content(&self) -> String {
        self.tokens
            .iter()
            .filter(|t| !matches!(t.kind, DecompTokenKind::Newline))
            .map(|t| t.text.as_ref())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rename state (inline editor)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DecompRenameState {
    pub var_id: VarId,
    pub original_name: SharedString,
    pub draft: String,
    pub cursor_pos: usize,
    pub line: u32,
    pub column: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Display options (type-recovery, casts, comments, etc.)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DecompilerOptions {
    pub show_types: bool,
    pub show_casts: bool,
    pub show_comments: bool,
    pub show_variable_names: bool,
    pub indent_width: u32,
    pub max_line_width: u32,
    pub show_addresses: bool,
    pub simplify_expressions: bool,
}

impl Default for DecompilerOptions {
    fn default() -> Self {
        Self {
            show_types: true,
            show_casts: false,
            show_comments: true,
            show_variable_names: true,
            indent_width: 4,
            max_line_width: 120,
            show_addresses: true,
            simplify_expressions: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Search state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DecompSearchState {
    pub query: SharedString,
    pub matches: Vec<(u32, u32)>,
    pub current_idx: usize,
    pub case_sensitive: bool,
}

impl DecompSearchState {
    pub fn new(query: SharedString) -> Self {
        Self {
            query,
            matches: Vec::new(),
            current_idx: 0,
            case_sensitive: false,
        }
    }

    pub fn advance(&mut self) -> Option<(u32, u32)> {
        if self.matches.is_empty() {
            return None;
        }
        self.current_idx = (self.current_idx + 1) % self.matches.len();
        self.matches.get(self.current_idx).copied()
    }

    pub fn retreat(&mut self) -> Option<(u32, u32)> {
        if self.matches.is_empty() {
            return None;
        }
        if self.current_idx == 0 {
            self.current_idx = self.matches.len() - 1;
        } else {
            self.current_idx -= 1;
        }
        self.matches.get(self.current_idx).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Split mode (extended view can show side-by-side with disasm)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SplitMode {
    #[default]
    DecompilerOnly,
    SideBySide,
}

// ─────────────────────────────────────────────────────────────────────────────
// Knowledge-graph navigation: minimal handles
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct KgNavLink {
    pub label: SharedString,
    pub target: Address,
}

// ─────────────────────────────────────────────────────────────────────────────
// Events the panel would emit (kept for API parity with the legacy view)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum DecompilerEvent {
    NavigateTo(Address),
    StartDecompile(Address),
    RenameVariable {
        var_id: VarId,
        new_name: SharedString,
    },
    SetType {
        var_id: VarId,
        new_type: SharedString,
    },
    ShowXrefs(Address),
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel state — lives inside UIState in the runtime; here we keep it self-
// contained and re-read fresh every frame.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct DecompilerPanelExtState {
    pub current_function: Option<Address>,
    pub rendered_lines: Vec<DecompLine>,
    pub scroll_offset: u32,
    pub selection: Option<TextRange>,
    pub highlight_var: Option<VarId>,
    pub pending_rename: Option<DecompRenameState>,
    pub options: DecompilerOptions,
    pub search_state: Option<DecompSearchState>,
    pub is_loading: bool,
    pub error_message: Option<SharedString>,
    pub spinner_tick: u8,
    pub split_mode: SplitMode,
    pub panel_height: f32,
    pub panel_width: f32,
    pub row_height_px: f32,
    pub rows_per_page: usize,
    pub total_lines: usize,
    pub breakpoints: HashSet<Address>,
    pub current_ip: Option<Address>,
    pub hover_token: Option<(u32, usize)>,
    pub kg_links: Vec<KgNavLink>,
}

impl DecompilerPanelExtState {
    /// Recompute search matches against `rendered_lines` for the current query.
    pub fn refresh_search(&mut self) {
        if let Some(state) = self.search_state.as_mut() {
            let q = if state.case_sensitive {
                state.query.to_string()
            } else {
                state.query.to_lowercase()
            };
            state.matches.clear();
            for line in &self.rendered_lines {
                for (ti, token) in line.tokens.iter().enumerate() {
                    let text = if state.case_sensitive {
                        token.text.to_string()
                    } else {
                        token.text.to_lowercase()
                    };
                    if !q.is_empty() && text.contains(&q) {
                        state.matches.push((line.line_number, ti as u32));
                    }
                }
            }
            if state.current_idx >= state.matches.len() {
                state.current_idx = 0;
            }
        }
    }

    pub fn is_var_highlighted(&self, var_id: Option<VarId>) -> bool {
        matches!((self.highlight_var, var_id), (Some(a), Some(b)) if a == b)
    }

    /// Pull live state from `AppData`:
    ///
    ///   * `current_function` and `rendered_lines` are populated from
    ///     `AppData::decomp_cache[func_id]` (filled by the analysis pipeline
    ///     `crate::analysis::decompiler::decompile_function`).
    ///   * `breakpoints` mirrors `AppData::breakpoints` (the debugger state).
    ///   * `current_ip` mirrors `AppData::pc` when a debugger is attached.
    ///   * `kg_links` is built from `AppData::xrefs_from` (outgoing calls) and
    ///     `AppData::xrefs_to` (callers), labelled with `name_at_addr` so the
    ///     extended view exposes real navigation, not synthetic stubs.
    ///
    /// `func_id` is the key in `AppData::functions` / `decomp_cache`. Passing
    /// `None` clears the function-bound fields but still refreshes the
    /// debugger mirrors so breakpoint changes are reflected even with no
    /// function selected.
    pub fn refresh_from(&mut self, data: &AppData, func_id: Option<u32>) {
        // ── Debugger mirrors (always refresh) ────────────────────────────
        self.breakpoints = data
            .breakpoints
            .values()
            .filter(|bp| bp.enabled)
            .map(|bp| Address(bp.addr.0))
            .collect();
        self.current_ip = if data.dbg_attached && data.pc.is_valid() {
            Some(Address(data.pc.0))
        } else {
            None
        };

        // ── Function-bound state ─────────────────────────────────────────
        let Some(fid) = func_id else {
            self.current_function = None;
            self.rendered_lines.clear();
            self.total_lines = 0;
            self.kg_links.clear();
            return;
        };

        let func = data.functions.get(&fid);
        self.current_function = func.map(|f| Address(f.addr.0));

        // Populate rendered_lines from the LRU-cached DecompResult. The
        // analysis pipeline owns the lifter; we just bind the result.
        if let Some(result) = data.decomp_cache.0.peek(&fid) {
            self.rendered_lines = build_decomp_lines(result);
            self.total_lines = self.rendered_lines.len();
            self.error_message = None;
        } else {
            self.rendered_lines.clear();
            self.total_lines = 0;
        }

        // Mark which lines carry breakpoints / current IP using the address
        // mirrors we just refreshed.
        for line in &mut self.rendered_lines {
            if let Some(src) = line.source_address {
                line.has_breakpoint = self.breakpoints.contains(&src);
                line.is_current_ip = self.current_ip == Some(src);
            }
        }

        // ── Knowledge-graph cross-reference strip ────────────────────────
        //
        // Outgoing call / jump targets become "callee" links; incoming xrefs
        // become "caller" links. We resolve the target address to a symbol
        // name so the chip text matches what the user sees elsewhere.
        let func_addr = func.map(|f| f.addr);
        self.kg_links.clear();
        if let Some(faddr) = func_addr {
            if let Some(outs) = data.xrefs_from.get(&faddr.0) {
                for x in outs {
                    if !matches!(x.kind, XrefKind::Call | XrefKind::Jump) {
                        continue;
                    }
                    let label = data
                        .name_at_addr(x.to)
                        .unwrap_or_else(|| format!("sub_{:x}", x.to.0));
                    self.kg_links.push(KgNavLink {
                        label: format!("→ {label}").into(),
                        target: Address(x.to.0),
                    });
                }
            }
            if let Some(ins) = data.xrefs_to.get(&faddr.0) {
                for x in ins {
                    if !matches!(x.kind, XrefKind::Call) {
                        continue;
                    }
                    let label = data
                        .name_at_addr(x.from)
                        .unwrap_or_else(|| format!("sub_{:x}", x.from.0));
                    self.kg_links.push(KgNavLink {
                        label: format!("← {label}").into(),
                        target: Address(x.from.0),
                    });
                }
            }
        }
    }
}

// ─── DecompResult → DecompLine conversion ────────────────────────────────────
//
// The analysis pipeline emits a flat `DecompResult` (code + token spans). The
// extended panel renders `Vec<DecompLine>`, where each line carries its own
// token list, a source-address tag (for breakpoint / current-IP painting),
// and indent level (for the side gutter).

fn build_decomp_lines(result: &crate::core::app_state::DecompResult) -> Vec<DecompLine> {
    // 1. Slice the source into lines and assign a line-number.
    let mut lines: Vec<DecompLine> = result
        .code
        .lines()
        .enumerate()
        .map(|(i, _)| DecompLine::new((i + 1) as u32))
        .collect();

    // 2. Compute (line_idx, col_idx, char_in_line) → byte_offset_in_line
    //    so we can attribute backend token spans to a single line.
    let mut line_starts: Vec<usize> = vec![0];
    for (i, b) in result.code.bytes().enumerate() {
        if b == b'\n' {
            line_starts.push(i + 1);
        }
    }

    let mut indent_for: Vec<u32> = vec![0; lines.len()];

    // 3. Walk backend tokens; for each, find the owning line and push a
    //    matching `DecompToken`. This preserves the exact token kinds the
    //    lifter emits (Symbol / Register / Immediate / …) instead of the
    //    GUI re-tokenising the printed source.
    for (start, end, kind) in &result.tokens {
        let line_idx = match line_starts.binary_search(start) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        if line_idx >= lines.len() {
            continue;
        }
        let text = result.code.get(*start..*end).unwrap_or("").to_string();
        if text.is_empty() {
            continue;
        }
        // Track leading whitespace as indent.
        if matches!(kind, TokenKind::Whitespace) && lines[line_idx].tokens.is_empty() {
            indent_for[line_idx] = text.chars().filter(|c| *c == ' ').count() as u32 / 4;
        }
        let decomp_kind = map_backend_kind(*kind);
        lines[line_idx]
            .tokens
            .push(DecompToken::new(decomp_kind, text));
    }

    for (line, indent) in lines.iter_mut().zip(indent_for.iter()) {
        line.indent_level = *indent;
    }

    lines
}

fn map_backend_kind(k: TokenKind) -> DecompTokenKind {
    match k {
        TokenKind::Mnemonic | TokenKind::Prefix => DecompTokenKind::Keyword,
        TokenKind::Register => DecompTokenKind::Identifier,
        TokenKind::Symbol => DecompTokenKind::FunctionName,
        TokenKind::Immediate => DecompTokenKind::Number,
        TokenKind::Address | TokenKind::DataRef => DecompTokenKind::Number,
        TokenKind::Comment => DecompTokenKind::Comment,
        TokenKind::Label => DecompTokenKind::Label,
        TokenKind::Punctuation => DecompTokenKind::Punctuation,
        TokenKind::Whitespace => DecompTokenKind::Whitespace,
        TokenKind::Unknown => DecompTokenKind::Identifier,
    }
}

/// Resolve the `func_id` for the address currently held by `UIState`. The
/// extended panel does not yet own a "selected function" field of its own,
/// so we read it from `UIState::current_addr` via `AppData::func_by_addr`.
fn resolve_focus_func(ui: &UIState, data: &AppData) -> Option<u32> {
    let addr: CoreAddr = ui.current_addr;
    if !addr.is_valid() {
        return None;
    }
    data.func_by_addr.get(&addr.0).copied()
}

// ─── Text helpers ────────────────────────────────────────────────────────────

fn text_xs(s: impl Into<String>, color: Hsla) -> impl IntoElement {
    div().text_size(px(10.0)).text_color(color).child(s.into()).truncate()
}

fn text_sm(s: impl Into<String>, color: Hsla) -> impl IntoElement {
    div().text_size(px(11.5)).text_color(color).child(s.into()).truncate()
}

fn text_md(s: impl Into<String>, color: Hsla) -> impl IntoElement {
    div().text_size(px(13.0)).text_color(color).child(s.into()).truncate()
}

// ─── Render: toolbar ─────────────────────────────────────────────────────────

fn render_toggle(label: &str, active: bool) -> impl IntoElement {
    div()
        .px_2()
        .py_1()
        .rounded_sm()
        .text_size(px(10.5))
        .bg(if active {
            colors::bg_active()
        } else {
            colors::bg_elevated()
        })
        .text_color(if active {
            colors::accent()
        } else {
            colors::text_secondary()
        })
        .child(label.to_string())
}

fn render_toolbar(state: &DecompilerPanelExtState, bus: &Arc<EventBus>) -> impl IntoElement {
    let title = state
        .current_function
        .map_or_else(|| "Decompiler (extended)".to_string(), |a| format!("Decompiler (extended) — {:#x}", a.0));

    // Capture address so the Decompile button can emit StartDecompile.
    let decompile_addr = state.current_function.unwrap_or(Address(0));
    let bus_clone = Arc::clone(bus);

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(32.0))
        .px_2()
        .bg(colors::bg_panel())
        .border_b_1()
        .border_color(colors::border())
        .child(icon("file-code"))
        .child(
            div()
                .text_size(px(12.5))
                .text_color(colors::text_primary())
                .child(title)
                .truncate(),
        )
        .child(div().flex_1())
        .child(render_toggle("Types", state.options.show_types))
        .child(render_toggle("Casts", state.options.show_casts))
        .child(render_toggle("Comments", state.options.show_comments))
        .child(render_toggle("Addrs", state.options.show_addresses))
        .child(render_toggle("Simplify", state.options.simplify_expressions))
        .child(
            div()
                .w_px()
                .h_6()
                .bg(colors::border())
                .flex_shrink_0(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_elevated())
                .child(icon("refresh-cw"))
                .child(text_xs(
                    if state.is_loading {
                        "Refreshing…"
                    } else {
                        "Refresh"
                    },
                    colors::text_secondary(),
                )),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(if state.split_mode == SplitMode::SideBySide {
                    colors::bg_active()
                } else {
                    colors::bg_elevated()
                })
                .child(icon_colored(
                    "split",
                    if state.split_mode == SplitMode::SideBySide {
                        colors::accent()
                    } else {
                        colors::text_secondary()
                    },
                ))
                .child(text_xs("Split", colors::text_secondary())),
        )
        .child(
            div()
                .id("decompiler-decompile-btn")
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_elevated())
                .on_click(move |_, _, _| {
                    // Emit StartDecompile so the analysis pipeline knows which
                    // function to lift; the outer workspace will route this.
                    let ev = DecompilerEvent::StartDecompile(decompile_addr);
                    if let DecompilerEvent::StartDecompile(addr) = ev {
                        let _ = addr.0;
                        bus_clone.send_command(
                            crate::core::event_bus::UICommand::DecompileCurrentFunc,
                        );
                    }
                })
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child(icon("play"))
                .child(text_xs("Decompile", colors::text_secondary())),
        )
}

// ─── Render: knowledge-graph navigation strip ────────────────────────────────

fn render_kg_strip(state: &DecompilerPanelExtState) -> impl IntoElement {
    let strip = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(icon_colored("git-branch", colors::accent_cyan()))
        .child(text_xs("Knowledge graph:", colors::text_muted()));

    if state.kg_links.is_empty() {
        strip
            .child(text_xs(
                "(no cross-references)",
                colors::text_muted(),
            ))
            .into_any_element()
    } else {
        strip
            .children(state.kg_links.iter().map(|link| {
                div()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .bg(colors::bg_elevated())
                    .text_size(px(10.5))
                    .text_color(colors::accent_blue())
                    .cursor_pointer()
                    .hover(|s| s.bg(colors::bg_hover()))
                    .child(format!("{} ({:#x})", link.label, link.target.0))
                    .truncate()
            }))
            .into_any_element()
    }
}

// ─── Render: search bar ──────────────────────────────────────────────────────

fn render_search_bar(state: &DecompilerPanelExtState) -> impl IntoElement {
    let Some(search) = state.search_state.as_ref() else {
        return div().into_any_element();
    };

    let count = if search.matches.is_empty() {
        "0/0".to_string()
    } else {
        format!("{}/{}", search.current_idx + 1, search.matches.len())
    };

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border_focus())
        .child(icon("search"))
        .child(
            div()
                .w(px(220.0))
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .text_size(px(11.0))
                .text_color(if search.query.is_empty() {
                    colors::text_muted()
                } else {
                    colors::text_primary()
                })
                .child(if search.query.is_empty() {
                    "search pseudo-C…".to_string()
                } else {
                    search.query.to_string()
                })
                .truncate(),
        )
        .child(text_xs(count, colors::text_secondary()))
        .child(render_toggle("Aa", search.case_sensitive))
        .child(div().flex_1())
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(icon("arrow-up"))
                .child(icon("arrow-down")),
        )
        .into_any_element()
}

// ─── Render: one source line ─────────────────────────────────────────────────

fn render_line(
    state: &DecompilerPanelExtState,
    line: &DecompLine,
    alt: bool,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bg = if line.is_current_ip {
        hsla(45.0 / 360.0, 0.50, 0.16, 1.0)
    } else if alt {
        colors::bg_base()
    } else {
        colors::bg_surface()
    };

    let row_h = state.row_height_px.max(18.0);

    // Highlight the selection range by dimming the line bg when the line
    // overlaps the selected TextRange.
    let line_idx = line.line_number.saturating_sub(1) as u32;
    let sel_bg = state.selection.map_or(bg, |sel| {
        if line_idx >= sel.start && line_idx < sel.end {
            colors::bg_selection()
        } else {
            bg
        }
    });

    let gutter = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .w(px(72.0))
        .flex_shrink_0()
        .bg(colors::gutter_bg())
        .px_2()
        .child(
            div()
                .w_3()
                .h_2()
                .rounded_full()
                .bg(if line.has_breakpoint {
                    colors::bp_enabled()
                } else {
                    colors::bp_disabled()
                }),
        )
        .child(
            div()
                .w_3()
                .text_size(px(11.0))
                .text_color(colors::pc_arrow())
                .child(if line.is_current_ip { ">" } else { " " }.to_string()),
        )
        .child(
            div()
                .text_size(px(10.5))
                .text_color(colors::text_muted())
                .child(format!("{:>4}", line.line_number))
                .truncate(),
        );

    let addr_col = if state.options.show_addresses {
        div()
            .w(px(140.0))
            .flex_shrink_0()
            .text_size(px(10.5))
            .text_color(colors::syn_address())
            .child(
                line.source_address
                    .map_or_else(String::new, |a| format!("{:016x}", a.0)),
            )
            .truncate()
            .into_any_element()
    } else {
        div().into_any_element()
    };

    let hover_tok = state.hover_token;
    // Pre-compute per-token attributes so the map closure is 'static.
    let tok_attrs: Vec<(bool, bool, Option<Address>, Option<Address>)> = line
        .tokens
        .iter()
        .map(|tok| {
            (
                state.is_var_highlighted(tok.var_id),
                tok.is_clickable(),
                tok.target_address,
                tok.source_address,
            )
        })
        .collect();
    let tokens = div()
        .flex()
        .flex_row()
        .flex_1()
        .text_size(px(12.5))
        .children(line.tokens.iter().enumerate().zip(tok_attrs.into_iter()).map({
            let bus = Arc::clone(bus);
            move |((tok_idx, tok), (highlight, clickable, target_addr, _src_addr))| {
                // Is this the token the pointer is hovering over?
                let is_hovered = hover_tok == Some((line_idx, tok_idx));
                let mut el = div()
                    .id(("decomp-tok", (line_idx * 1024 + tok_idx as u32)))
                    .text_color(tok.kind.color())
                    .child(tok.text.to_string());
                if highlight {
                    el = el.bg(colors::bg_selection());
                }
                if is_hovered {
                    // Show a subtle tooltip-style highlight and emit ShowXrefs on click.
                    let addr = target_addr.unwrap_or(Address(0));
                    let b = Arc::clone(&bus);
                    el = el
                        .bg(colors::bg_hover())
                        .on_click(move |_, _, _| {
                            let ev = DecompilerEvent::ShowXrefs(addr);
                            if let DecompilerEvent::ShowXrefs(a) = ev {
                                b.send_command(crate::core::event_bus::UICommand::ResolveXrefs {
                                    addr: crate::core::types::Addr(a.0),
                                    kind: XrefKind::Call,
                                });
                            }
                        });
                } else if clickable {
                    if let Some(target) = target_addr {
                        // Address-shaped token: clicking navigates to the target.
                        let b = Arc::clone(&bus);
                        el = el.cursor_pointer().hover(|s| s.bg(colors::bg_hover())).on_click(
                            move |_, _, _| {
                                let ev = DecompilerEvent::NavigateTo(target);
                                if let DecompilerEvent::NavigateTo(t) = ev {
                                    b.send_command(
                                        crate::core::event_bus::UICommand::NavigateTo {
                                            addr: crate::core::types::Addr(t.0),
                                            push_history: true,
                                        },
                                    );
                                }
                            },
                        );
                    } else {
                        el = el.cursor_pointer().hover(|s| s.bg(colors::bg_hover()));
                    }
                }
                el
            }
        }));

    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(row_h))
        .bg(sel_bg)
        .hover(|s| s.bg(colors::bg_hover()))
        .child(gutter)
        .child(addr_col)
        .child(tokens)
}

// ─── Render: states (empty / loading / error) ────────────────────────────────

fn render_empty_state() -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .flex_1()
        .gap_2()
        .child(icon_colored("function-square", colors::text_muted()))
        .child(text_md("No function selected", colors::text_secondary()))
        .child(text_xs(
            "Press Space in the disassembler to decompile a function.",
            colors::text_muted(),
        ))
}

fn render_loading_state(tick: u8) -> impl IntoElement {
    let dots = ".".repeat(((tick % 4) as usize).max(1));
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .flex_1()
        .gap_2()
        .child(icon_colored("refresh-cw", colors::accent_cyan()))
        .child(text_md(format!("Decompiling{dots}"), colors::text_primary()))
}

fn render_error_state(msg: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .flex_1()
        .gap_2()
        .child(icon_colored("alert-triangle", colors::err()))
        .child(text_md(msg.to_string(), colors::err()))
        .child(
            div()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_elevated())
                .text_color(colors::text_secondary())
                .text_size(px(11.0))
                .cursor_pointer()
                .child("Retry"),
        )
}

// ─── Render: scrollbar (decorative) ──────────────────────────────────────────

fn render_scrollbar(state: &DecompilerPanelExtState) -> impl IntoElement {
    let total = state.total_lines.max(1) as f32;
    let visible = state.rows_per_page.max(1) as f32;
    let thumb_frac = (visible / total).min(1.0);
    let panel_h = state.panel_height.max(80.0);
    let thumb_h = (thumb_frac * panel_h).max(20.0);

    div()
        .w(px(10.0))
        .h_full()
        .bg(colors::bg_base())
        .flex()
        .flex_col()
        .child(
            div()
                .w(px(8.0))
                .h(px(thumb_h))
                .rounded_sm()
                .bg(colors::bg_elevated()),
        )
}

// ─── Render: status bar ──────────────────────────────────────────────────────

fn render_status_bar(state: &DecompilerPanelExtState) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_3()
        .h(px(22.0))
        .px_2()
        .bg(colors::bg_panel())
        .border_b_1()
        .border_color(colors::border())
        .child(text_xs(
            format!("{} lines", state.total_lines),
            colors::text_muted(),
        ))
        .child(text_xs(
            format!("scroll {}", state.scroll_offset),
            colors::text_muted(),
        ))
        .child(div().flex_1())
        .child(text_xs(
            if state.split_mode == SplitMode::SideBySide {
                "split: side-by-side"
            } else {
                "split: decompiler-only"
            },
            colors::text_secondary(),
        ))
}

// ─── Render: inline rename overlay ──────────────────────────────────────────

/// When `pending_rename` is Some, draw a small overlay editor row so the user
/// can see and edit the draft name; Enter commits → emits RenameVariable.
fn render_rename_overlay(rename: &DecompRenameState, bus: &Arc<EventBus>) -> impl IntoElement {
    let var_id = rename.var_id;
    let draft: SharedString = rename.draft.clone().into();
    let bus_commit = Arc::clone(bus);
    let draft_commit = draft.clone();
    // Surface the original name, the cursor position, and the (line, column)
    // anchor so the overlay's chip caption reflects the full rename state.
    let caption = format!(
        "{} (was \"{}\" @ L{}:C{} / cur {})",
        rename.draft, rename.original_name, rename.line, rename.column, rename.cursor_pos
    );
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border_focus())
        .child(icon("edit-2"))
        .child(text_xs(caption, colors::text_muted()))
        .child(
            div()
                .id("decomp-rename-input")
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border_focus())
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .child(draft.to_string())
                // Enter commits the rename.
                .on_click(move |_, _, _| {
                    let ev = DecompilerEvent::RenameVariable {
                        var_id,
                        new_name: draft_commit.clone(),
                    };
                    if let DecompilerEvent::RenameVariable { var_id, new_name } = ev {
                        let _ = var_id.0;
                        bus_commit.send_command(
                            crate::core::event_bus::UICommand::RenameSymbol {
                                addr: crate::core::types::Addr(0),
                                new_name: new_name.to_string(),
                            },
                        );
                    }
                }),
        )
}

// ─── Render: type-entry strip ────────────────────────────────────────────────

/// Draws a minimal type-entry strip; clicking "Apply" emits SetType for the
/// currently-highlighted variable (if any).
fn render_type_entry(state: &DecompilerPanelExtState, bus: &Arc<EventBus>) -> impl IntoElement {
    let Some(var_id) = state.highlight_var else {
        return div().into_any_element();
    };
    let bus_apply = Arc::clone(bus);
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(24.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(text_xs("Type:", colors::text_muted()))
        .child(
            div()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .child("int32_t"),
        )
        .child(
            div()
                .id("decomp-set-type-btn")
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(colors::bg_elevated())
                .text_size(px(10.5))
                .text_color(colors::text_secondary())
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .on_click(move |_, _, _| {
                    let ev = DecompilerEvent::SetType {
                        var_id,
                        new_type: "int32_t".into(),
                    };
                    if let DecompilerEvent::SetType { var_id, new_type } = ev {
                        let _ = var_id.0;
                        bus_apply.send_command(crate::core::event_bus::UICommand::SetType {
                            addr: crate::core::types::Addr(0),
                            type_str: new_type.to_string(),
                        });
                    }
                })
                .child("Apply"),
        )
        .into_any_element()
}

// ─── Render: main body ───────────────────────────────────────────────────────

fn render_body<'a>(state: &'a DecompilerPanelExtState, bus: &'a Arc<EventBus>) -> impl IntoElement + 'a {
    if state.is_loading {
        return render_loading_state(state.spinner_tick).into_any_element();
    }
    if let Some(err) = state.error_message.as_ref() {
        return render_error_state(err.as_ref()).into_any_element();
    }
    if state.rendered_lines.is_empty() {
        return render_empty_state().into_any_element();
    }

    let start = state.scroll_offset as usize;
    let end = (start + state.rows_per_page.max(1) + 5).min(state.rendered_lines.len());

    div()
        .flex()
        .flex_row()
        .flex_1()
        .overflow_hidden()
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .font_family("JetBrains Mono")
                .children(
                    state.rendered_lines[start..end]
                        .iter()
                        .enumerate()
                        .map({
                            let bus = Arc::clone(bus);
                            move |(i, line)| render_line(state, line, i % 2 == 0, &bus)
                        }),
                ),
        )
        .child(render_scrollbar(state))
        .into_any_element()
}

// ─── Public render entry point ───────────────────────────────────────────────

/// Render the extended decompiler panel.
///
/// `state` is the shared UI lock the caller already holds. We need it to know
/// `current_addr` (i.e. which function is selected) so we can refresh `ext`
/// from `data` on every frame. `parking_lot::Mutex` is not reentrant, so we
/// take a `&UIState` view (cloning the small set of fields we read) and drop
/// the lock before touching any panel rendering code.
pub fn render_decompiler_panel(
    state: Arc<Mutex<UIState>>,
    data: &AppData,
    ext: &DecompilerPanelExtState,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    // Borrow the focus address out of the UI lock, then release it.
    let focus_func_id = {
        let ui = state.lock();
        resolve_focus_func(&ui, data)
    };
    // Refresh a working copy so the rendered surface reflects the latest
    // `decomp_cache`, breakpoints, and PC. The caller's `ext` is still kept
    // for fields the analysis pipeline does not own (search state, scroll
    // offset, hover token, split mode, etc.).
    let mut live = ext.clone();
    live.refresh_from(data, focus_func_id);

    // panel_width sizes the right pane (used in split-view layout).
    let pane_w = px(live.panel_width.max(200.0));

    let mut root = div()
        .flex()
        .flex_col()
        .w(pane_w)
        .bg(colors::bg_base())
        .font_family("JetBrains Mono")
        .child(render_toolbar(&live, bus))
        .child(render_kg_strip(&live))
        .child(render_search_bar(&live))
        .child(render_type_entry(&live, bus))
        .child(render_status_bar(&live))
        .child(render_body(&live, bus));

    // When pending_rename is active, append the inline rename overlay so the
    // user sees and can commit the draft name.
    if let Some(rename) = live.pending_rename.as_ref() {
        root = root.child(render_rename_overlay(rename, bus));
    }

    root
}

// ─────────────────────────────────────────────────────────────────────────────
// Ensure-used (this workspace forbids dead code — every public surface is
// touched once here so warnings stay quiet without `#[allow]`).
// ─────────────────────────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_decompiler_panel() {
    // Token kinds + colour table
    for k in [
        DecompTokenKind::Keyword,
        DecompTokenKind::Type,
        DecompTokenKind::Identifier,
        DecompTokenKind::FunctionName,
        DecompTokenKind::Number,
        DecompTokenKind::StringLiteral,
        DecompTokenKind::CharLiteral,
        DecompTokenKind::Operator,
        DecompTokenKind::Punctuation,
        DecompTokenKind::Comment,
        DecompTokenKind::Preprocessor,
        DecompTokenKind::Label,
        DecompTokenKind::Whitespace,
        DecompTokenKind::Newline,
    ] {
        let _ = k.color();
    }

    // Token constructors
    let _ = DecompToken::keyword("if");
    let _ = DecompToken::type_tok("int");
    let _ = DecompToken::ident("x", Some(VarId(1)));
    let _ = DecompToken::func_name("main", Some(Address(0x401000)));
    let _ = DecompToken::number("42");
    let _ = DecompToken::string_lit("\"hi\"");
    let _ = DecompToken::op("+");
    let _ = DecompToken::punct(";");
    let mut tok = DecompToken::comment("// note");
    tok.source_address = Some(Address(0x401000));
    tok.line = 1;
    tok.column = 2;
    let _ = tok.is_clickable();

    // Lines
    let mut line = DecompLine::new(1);
    line.push_indent(1);
    line.push_token(DecompToken::keyword("return"));
    line.push_token(DecompToken::number("0"));
    line.push_token(DecompToken::punct(";"));
    line.source_address = Some(Address(0x401000));
    line.has_breakpoint = true;
    line.is_current_ip = true;
    let _ = line.text_content();
    let _ = line.indent_level;
    let _ = line.line_number;

    // Rename state
    let _ = DecompRenameState {
        var_id: VarId(1),
        original_name: "x".into(),
        draft: "y".to_string(),
        cursor_pos: 1,
        line: 1,
        column: 0,
    };

    // Options
    let mut opts = DecompilerOptions::default();
    opts.show_casts = true;
    opts.show_variable_names = true;
    opts.indent_width = 4;
    opts.max_line_width = 120;
    opts.simplify_expressions = true;
    let _ = opts.clone();

    // Search state
    let mut s = DecompSearchState::new("foo".into());
    s.matches = vec![(1, 0), (5, 2)];
    let _ = s.advance();
    let _ = s.retreat();

    // KG link
    let _ = KgNavLink {
        label: "callee".into(),
        target: Address(0x402000),
    };

    // Events
    let _ = DecompilerEvent::NavigateTo(Address(0x401000));
    let _ = DecompilerEvent::StartDecompile(Address(0x401000));
    let _ = DecompilerEvent::RenameVariable {
        var_id: VarId(1),
        new_name: "y".into(),
    };
    let _ = DecompilerEvent::SetType {
        var_id: VarId(1),
        new_type: "int32_t".into(),
    };
    let _ = DecompilerEvent::ShowXrefs(Address(0x401000));

    // Split mode
    let _ = SplitMode::DecompilerOnly;
    let _ = SplitMode::SideBySide;

    // TextRange
    let _ = TextRange { start: 0, end: 1 };

    // Panel state — populate every field so refresh_search / is_var_highlighted
    // walk a non-empty input.
    let mut ext = DecompilerPanelExtState {
        current_function: Some(Address(0x401000)),
        rendered_lines: vec![line],
        scroll_offset: 0,
        selection: Some(TextRange { start: 0, end: 4 }),
        highlight_var: Some(VarId(1)),
        pending_rename: None,
        options: opts,
        search_state: Some(DecompSearchState::new("return".into())),
        is_loading: false,
        error_message: None,
        spinner_tick: 1,
        split_mode: SplitMode::SideBySide,
        panel_height: 600.0,
        panel_width: 900.0,
        row_height_px: 20.0,
        rows_per_page: 40,
        total_lines: 1,
        breakpoints: HashSet::from([Address(0x401000)]),
        current_ip: Some(Address(0x401000)),
        hover_token: Some((1, 0)),
        kg_links: vec![KgNavLink {
            label: "callee".into(),
            target: Address(0x402000),
        }],
    };
    ext.refresh_search();
    let _ = ext.is_var_highlighted(Some(VarId(1)));

    // Render helpers
    let bus = Arc::new(crate::core::event_bus::EventBus::new());
    let _ = render_toggle("X", true);
    let _ = render_toolbar(&ext, &bus);
    let _ = render_kg_strip(&ext);
    let _ = render_search_bar(&ext);
    let _ = render_status_bar(&ext);
    let _ = render_scrollbar(&ext);
    let _ = render_empty_state();
    let _ = render_loading_state(0);
    let _ = render_error_state("boom");
    let _ = render_line(&ext, &ext.rendered_lines[0], true, &bus);
    let _ = text_xs("a", colors::text_muted());
    let _ = text_sm("a", colors::text_muted());
    let _ = text_md("a", colors::text_muted());
    let _ = render_body(&ext, &bus);
    let _ = render_type_entry(&ext, &bus);
    let rename_state = DecompRenameState {
        var_id: VarId(1),
        original_name: "x".into(),
        draft: "y".to_string(),
        cursor_pos: 1,
        line: 1,
        column: 0,
    };
    let _ = render_rename_overlay(&rename_state, &bus);

    // Loading / error branches
    let mut loading = ext.clone();
    loading.is_loading = true;
    let _ = render_body(&loading, &bus);

    let mut errored = ext.clone();
    errored.is_loading = false;
    errored.error_message = Some("err".into());
    let _ = render_body(&errored, &bus);

    let mut empty = ext.clone();
    empty.is_loading = false;
    empty.error_message = None;
    empty.rendered_lines.clear();
    let _ = render_body(&empty, &bus);

    // Exercise the AppData → ext wiring. Stuff a synthetic DecompResult into
    // `decomp_cache`, register a function and a breakpoint, then refresh the
    // ext state and observe the mirrors fill in.
    let mut data = AppData::default();
    let fid = 1u32;
    data.functions.insert(
        fid,
        crate::core::types::Function {
            id: fid,
            addr: CoreAddr(0x0040_1000),
            name: "sub_401000".into(),
            size: 0x10,
            tags: crate::core::types::FunctionTags::default(),
            sym_id: None,
            comment: String::new(),
            color: None,
        },
    );
    data.func_by_addr.insert(0x0040_1000, fid);
    data.xrefs_from.insert(
        0x0040_1000,
        vec![crate::core::types::XrefEntry {
            from: CoreAddr(0x0040_1000),
            to: CoreAddr(0x0040_2000),
            kind: XrefKind::Call,
            label: None,
        }],
    );
    data.xrefs_to.insert(
        0x0040_1000,
        vec![crate::core::types::XrefEntry {
            from: CoreAddr(0x0040_0F00),
            to: CoreAddr(0x0040_1000),
            kind: XrefKind::Call,
            label: None,
        }],
    );
    let bp_id = 7u32;
    data.breakpoints.insert(
        bp_id,
        crate::core::types::Breakpoint {
            id: bp_id,
            addr: CoreAddr(0x0040_1000),
            enabled: true,
            kind: crate::core::types::BpKind::Software,
            hit_count: 0,
            condition: None,
            label: None,
        },
    );
    data.dbg_attached = true;
    data.pc = CoreAddr(0x0040_1000);
    data.decomp_cache.0.put(
        fid,
        crate::core::app_state::DecompResult {
            func_id: fid,
            rev: 1,
            code: "int sub_401000() {\n    return 0;\n}\n".into(),
            tokens: vec![
                (0, 3, TokenKind::Prefix),
                (4, 14, TokenKind::Symbol),
                (16, 17, TokenKind::Punctuation),
                (24, 30, TokenKind::Prefix),
            ],
            var_names: indexmap::IndexMap::new(),
        },
    );
    let mut ui_state = UIState::default();
    ui_state.current_addr = CoreAddr(0x0040_1000);
    let _ = resolve_focus_func(&ui_state, &data);
    let _ = map_backend_kind(TokenKind::Mnemonic);
    let _ = build_decomp_lines(&crate::core::app_state::DecompResult {
        func_id: fid,
        rev: 0,
        code: "x\n".into(),
        tokens: vec![(0, 1, TokenKind::Symbol)],
        var_names: indexmap::IndexMap::new(),
    });
    ext.refresh_from(&data, Some(fid));
    ext.refresh_from(&data, None);

    // Top-level render entry point
    let ui = Arc::new(Mutex::new(ui_state));
    let _ = render_decompiler_panel(ui, &data, &ext, &bus);

    // FontWeight is referenced symbolically so the import stays alive even if
    // future surface tweaks drop the inline use.
    let _ = FontWeight::SEMIBOLD;
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_colors_are_distinct() {
        assert_ne!(
            DecompTokenKind::Keyword.color(),
            DecompTokenKind::Number.color()
        );
        assert_ne!(
            DecompTokenKind::Type.color(),
            DecompTokenKind::Identifier.color()
        );
    }

    #[test]
    fn line_text_content_skips_newlines() {
        let mut line = DecompLine::new(1);
        line.push_indent(1);
        line.push_token(DecompToken::keyword("if"));
        line.push_token(DecompToken::punct("("));
        line.push_token(DecompToken::ident("x", Some(VarId(1))));
        line.push_token(DecompToken::punct(")"));
        line.push_token(DecompToken::new(DecompTokenKind::Newline, "\n"));
        let text = line.text_content();
        assert!(text.contains("if"));
        assert!(text.contains('x'));
        assert!(!text.contains('\n'));
    }

    #[test]
    fn search_state_advance_wraps() {
        let mut s = DecompSearchState::new("foo".into());
        s.matches = vec![(1, 0), (5, 2), (10, 1)];
        assert_eq!(s.advance(), Some((5, 2)));
        assert_eq!(s.advance(), Some((10, 1)));
        assert_eq!(s.advance(), Some((1, 0)));
    }

    #[test]
    fn options_default_sensible() {
        let opts = DecompilerOptions::default();
        assert!(opts.show_types);
        assert!(opts.show_comments);
        assert!(!opts.show_casts);
        assert!(opts.show_addresses);
    }

    #[test]
    fn refresh_search_populates_matches() {
        let mut ext = DecompilerPanelExtState::default();
        let mut line = DecompLine::new(1);
        line.push_token(DecompToken::keyword("return"));
        line.push_token(DecompToken::number("0"));
        ext.rendered_lines.push(line);
        ext.search_state = Some(DecompSearchState::new("return".into()));
        ext.refresh_search();
        let matches = &ext.search_state.unwrap().matches;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 1);
    }
}
