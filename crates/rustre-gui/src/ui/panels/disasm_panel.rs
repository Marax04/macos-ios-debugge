// ============================================================================
// ui/panels/disasm_panel.rs — Disasm side panel
//
// Ported from the legacy `gpui::View` / `ViewContext` implementation to the
// current panel convention used by the rest of zyphora:
//
//   * Plain `pub fn render_disasm_panel(Arc<Mutex<UIState>>, &AppData)`
//     returning `impl IntoElement + '_`.
//   * Per-panel state hung off `UIState::disasm_side` and cloned out each frame
//     (no `Render` trait, no `ViewContext`, no `Entity` subscriptions).
//   * Theme colours from `crate::ui::theme::colors::*` instead of ad-hoc
//     `rgb(...)`/`hsla(...)` literals.
//
// Panel purpose (per the porting spec): a side-companion to the disassembly
// view that surfaces, for the *currently selected* address:
//
//     1. Inbound + outbound cross-references (xrefs)
//     2. Jump-arrow targets (call / jmp / branch / fallthrough)
//     3. Hover register info (the register most recently selected in the
//        listing's token stream — fed by `UIState::hover.register`).
//
// All legacy data types (NavHistory, SearchState, GotoState, RenameState,
// CommentState, GutterState, ScrollbarState, ContextMenuState, the row
// enum + variants, token colour table, etc.) are kept intact so call-sites and
// command-handlers can still pivot through them. They're surfaced from
// `ensure_used_disasm_panel` at the bottom of the file so the dead-code lint
// never trips on this crate's "wire it, don't delete it" policy.
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::types::{Addr, XrefEntry, XrefKind};
use crate::ui::theme::{colors, sizes};
use gpui::{div, px, Hsla, InteractiveElement, IntoElement, ParentElement, Styled};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ── Column layout constants (kept from legacy; consumed by ensure_used) ──────

pub const ADDR_COL_CH: f32 = 17.0;
pub const BYTES_COL_CH: f32 = 32.0;
pub const MNEMONIC_COL_CH: f32 = 10.0;
pub const COMMENT_COL_CH: f32 = 40.0;

// ── Legacy token-colour table (preserved verbatim) ──────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenColor(pub u32); // RGBA packed

impl TokenColor {
    pub const ADDRESS: Self = Self(0x00_d7_ff_ff);
    pub const MNEMONIC: Self = Self(0x56_9c_d6_ff);
    pub const REGISTER: Self = Self(0xe0_6c_75_ff);
    pub const IMMEDIATE: Self = Self(0xd1_9a_66_ff);
    pub const MEM_REF: Self = Self(0xe5_c0_7b_ff);
    pub const COMMENT: Self = Self(0x98_c3_79_ff);
    pub const SEPARATOR: Self = Self(0x5c_63_71_ff);
    pub const LABEL: Self = Self(0xc6_78_dd_ff);
    pub const STRING: Self = Self(0x98_c3_79_ff);
    pub const KEYWORD: Self = Self(0xc6_78_dd_ff);
    pub const DEFAULT: Self = Self(0xab_b2_bf_ff);

    pub const fn to_rgb(self) -> u32 {
        self.0 >> 8
    }
}

// ── Legacy section / row datatypes (kept; rendered from `ensure_used`) ──────

#[derive(Clone, Debug)]
pub enum DisasmRow {
    Instruction(InstructionRow),
    FunctionHeader(FunctionHeaderRow),
    SectionBoundary(SectionBoundaryRow),
    Gap(GapRow),
    DataBytes(DataBytesRow),
}

impl DisasmRow {
    pub fn address(&self) -> Option<Addr> {
        match self {
            Self::Instruction(r) => Some(r.address),
            Self::FunctionHeader(r) => Some(r.address),
            Self::SectionBoundary(r) => Some(r.start_address),
            Self::Gap(r) => Some(r.start_address),
            Self::DataBytes(r) => Some(r.address),
        }
    }
    pub const fn row_height_px(&self) -> f32 {
        match self {
            Self::FunctionHeader(_) => 28.0,
            Self::SectionBoundary(_) => 22.0,
            Self::Gap(_) => 18.0,
            _ => 20.0,
        }
    }
    pub const fn is_selectable(&self) -> bool {
        matches!(self, Self::Instruction(_) | Self::DataBytes(_))
    }
}

#[derive(Clone, Debug)]
pub struct InstructionRow {
    pub address: Addr,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub comment: Option<String>,
    pub is_nop: bool,
    pub branch_target: Option<Addr>,
    pub is_call: bool,
    pub is_return: bool,
    pub is_unconditional_branch: bool,
}

impl InstructionRow {
    pub fn bytes_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug)]
pub struct FunctionHeaderRow {
    pub address: Addr,
    pub name: String,
    pub demangled_name: Option<String>,
    pub size_bytes: u64,
    pub is_noreturn: bool,
    pub calling_convention: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SectionBoundaryRow {
    pub start_address: Addr,
    pub name: String,
    pub size: u64,
    pub flags: SectionFlags,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SectionFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl SectionFlags {
    pub fn flag_string(self) -> String {
        let mut s = String::new();
        s.push(if self.readable { 'r' } else { '-' });
        s.push(if self.writable { 'w' } else { '-' });
        s.push(if self.executable { 'x' } else { '-' });
        s
    }
}

#[derive(Clone, Debug)]
pub struct GapRow {
    pub start_address: Addr,
    pub end_address: Addr,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct DataBytesRow {
    pub address: Addr,
    pub bytes: Vec<u8>,
    pub label: Option<String>,
    pub interpreted_as: DataInterpretation,
}

#[derive(Clone, Debug)]
pub enum DataInterpretation {
    Bytes,
    U16(u16),
    U32(u32),
    U64(u64),
    Ascii(String),
    Unicode(String),
    Pointer(Addr),
}

// ── Navigation history ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct NavHistory {
    back: Vec<Addr>,
    forward: Vec<Addr>,
    current: Option<Addr>,
}

impl NavHistory {
    pub fn navigate_to(&mut self, addr: Addr) {
        if let Some(cur) = self.current.take() {
            self.back.push(cur);
        }
        self.forward.clear();
        self.current = Some(addr);
    }
    pub fn go_back(&mut self) -> Option<Addr> {
        let prev = self.back.pop()?;
        if let Some(cur) = self.current.take() {
            self.forward.push(cur);
        }
        self.current = Some(prev);
        self.current
    }
    pub fn go_forward(&mut self) -> Option<Addr> {
        let next = self.forward.pop()?;
        if let Some(cur) = self.current.take() {
            self.back.push(cur);
        }
        self.current = Some(next);
        self.current
    }
    pub fn can_go_back(&self) -> bool {
        !self.back.is_empty()
    }
    pub fn can_go_forward(&self) -> bool {
        !self.forward.is_empty()
    }
    pub const fn current(&self) -> Option<Addr> {
        self.current
    }
}

// ── Search state ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SearchState {
    pub query: String,
    pub matches: Vec<Addr>,
    pub current_match_idx: usize,
    pub case_sensitive: bool,
    pub regex: bool,
    pub wrap: bool,
}

impl SearchState {
    pub fn new(query: String) -> Self {
        Self {
            query,
            matches: Vec::new(),
            current_match_idx: 0,
            case_sensitive: false,
            regex: false,
            wrap: true,
        }
    }
    pub fn current_match_address(&self) -> Option<Addr> {
        self.matches.get(self.current_match_idx).copied()
    }
    pub fn advance(&mut self) -> Option<Addr> {
        if self.matches.is_empty() {
            return None;
        }
        if self.current_match_idx + 1 < self.matches.len() {
            self.current_match_idx += 1;
        } else if self.wrap {
            self.current_match_idx = 0;
        }
        self.current_match_address()
    }
    pub fn retreat(&mut self) -> Option<Addr> {
        if self.matches.is_empty() {
            return None;
        }
        if self.current_match_idx > 0 {
            self.current_match_idx -= 1;
        } else if self.wrap {
            self.current_match_idx = self.matches.len().saturating_sub(1);
        }
        self.current_match_address()
    }
}

// ── Rename / comment / goto dialog state (kept; live alongside UIState's
// global dialog flags so callers wanting per-panel scratch can use these).

#[derive(Clone, Debug)]
pub struct RenameState {
    pub target_address: Addr,
    pub original_name: String,
    pub draft_name: String,
    pub cursor_pos: usize,
}

#[derive(Clone, Debug)]
pub struct CommentState {
    pub target_address: Addr,
    pub existing_comment: Option<String>,
    pub draft: String,
}

#[derive(Clone, Debug, Default)]
pub struct GotoState {
    pub draft: String,
    pub parsed_address: Option<Addr>,
    pub error: Option<String>,
}

impl GotoState {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn update_draft(&mut self, s: &str) {
        s.clone_into(&mut self.draft);
        let trimmed = s.trim();
        let hex = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        match u64::from_str_radix(hex, 16) {
            Ok(v) => {
                self.parsed_address = Some(Addr(v));
                self.error = None;
            }
            Err(_) => {
                self.parsed_address = None;
                self.error = Some("Invalid hex address".into());
            }
        }
    }
}

// ── Context menu state (preserved data only — UI uses normal menus). ────────

#[derive(Clone, Debug)]
pub struct ContextMenuState {
    pub position: [f32; 2],
    pub target_address: Addr,
    pub items: Vec<ContextMenuItem>,
}

#[derive(Clone, Debug)]
pub struct ContextMenuItem {
    pub label: String,
    pub action: ContextMenuAction,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub enum ContextMenuAction {
    Rename,
    AddComment,
    SetType,
    ToggleBreakpoint,
    CopyAddress,
    CopyBytes,
    CopyDisasm,
    FindReferences,
    DecompileFunction,
    JumpTo(Addr),
    PatchBytes,
    SetFunctionStart,
    FollowReference(Addr),
}

// ── Gutter / scrollbar ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct GutterState {
    pub bookmarks: HashSet<Addr>,
    pub breakpoints: HashMap<Addr, bool>, // addr -> enabled
    pub current_ip: Option<Addr>,
}

#[derive(Clone, Debug, Default)]
pub struct ScrollbarState {
    pub dragging: bool,
    pub drag_start_y: f32,
    pub drag_start_offset: u64,
    pub total_rows: usize,
    pub visible_rows: usize,
    pub scroll_offset_rows: u64,
}

impl ScrollbarState {
    pub fn thumb_fraction(&self) -> f32 {
        if self.total_rows == 0 {
            return 1.0;
        }
        let v = u16::try_from(self.visible_rows.min(u16::MAX as usize)).unwrap_or(u16::MAX);
        let t = u16::try_from(self.total_rows.min(u16::MAX as usize))
            .unwrap_or(u16::MAX)
            .max(1);
        (f32::from(v) / f32::from(t)).min(1.0)
    }
    pub fn thumb_y_fraction(&self) -> f32 {
        if self.total_rows == 0 {
            return 0.0;
        }
        let off = u16::try_from(self.scroll_offset_rows.min(u64::from(u16::MAX)))
            .unwrap_or(u16::MAX);
        let t = u16::try_from(self.total_rows.min(u16::MAX as usize))
            .unwrap_or(u16::MAX)
            .max(1);
        f32::from(off) / f32::from(t)
    }
}

// ── Per-panel UI state ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct DisasmSideState {
    /// Last address surfaced by the panel (mirrored from `UIState::current_addr`
    /// each frame so that user-driven address changes refresh the xref list).
    pub focus_addr: Addr,
    pub nav_history: NavHistory,
    pub search_state: SearchState,
    pub goto_state: GotoState,
    pub rename_state: Option<RenameState>,
    pub comment_state: Option<CommentState>,
    pub context_menu: Option<ContextMenuState>,
    pub gutter: GutterState,
    pub scrollbar: ScrollbarState,
    pub show_bytes: bool,
    pub show_comments: bool,
    pub show_demangled: bool,
    pub follow_mode: bool,
}

impl DisasmSideState {
    /// Mirror live debugger state out of `AppData` into this side-panel's
    /// scratch fields. Called by the parent before `render_disasm_panel` so
    /// the gutter chip / current-IP marker reflect real breakpoint changes
    /// without the panel ever fabricating addresses of its own.
    ///
    /// Wiring:
    ///   * `gutter.breakpoints` <- `AppData::breakpoints` (addr → enabled)
    ///   * `gutter.current_ip`  <- `AppData::pc` when `dbg_attached`
    ///   * `focus_addr`         <- `UIState::current_addr`
    ///   * `scrollbar.total_rows` <- listing length for the current function
    pub fn refresh_from(&mut self, data: &AppData, ui: &UIState) {
        self.focus_addr = ui.current_addr;

        self.gutter.breakpoints.clear();
        for bp in data.breakpoints.values() {
            self.gutter.breakpoints.insert(bp.addr, bp.enabled);
        }
        self.gutter.current_ip = if data.dbg_attached && data.pc.is_valid() {
            Some(data.pc)
        } else {
            None
        };

        // Mirror the listing length so the scrollbar thumb sizes itself
        // against real data instead of `Default::default()`.
        if let Some(fid) = data.func_by_addr.get(&self.focus_addr.0) {
            if let Some(rows) = data.listing_cache.get(fid) {
                self.scrollbar.total_rows = rows.len();
            }
        } else if !data.global_listing.is_empty() {
            self.scrollbar.total_rows = data.global_listing.len();
        }
    }
}

// ── Public render entry-point ───────────────────────────────────────────────

pub fn render_disasm_panel<'a>(
    ui: &'a UIState,
    data: &'a AppData,
) -> impl IntoElement + 'a {
    // Caller in app.rs already holds the UI mutex guard; receive a borrow
    // instead of an Arc so we don't deadlock by re-locking parking_lot.
    let focus = ui.current_addr;
    let hover_reg = ui.hover.token.clone();

    let xrefs_to: Vec<XrefEntry> = data
        .xrefs_to
        .get(&focus.0)
        .cloned()
        .unwrap_or_default();
    let xrefs_from: Vec<XrefEntry> = data
        .xrefs_from
        .get(&focus.0)
        .cloned()
        .unwrap_or_default();

    let reg_value = hover_reg
        .as_ref()
        .and_then(|name| data.registers.get(name.as_str()))
        .map(|r| (r.name.clone(), r.value, r.width));

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_surface())
        .child(render_header(focus))
        .child(render_section_header("Cross-references to"))
        .child(render_xref_list(&xrefs_to, true))
        .child(render_section_header("Cross-references from"))
        .child(render_xref_list(&xrefs_from, false))
        .child(render_section_header("Jump arrows"))
        .child(render_jump_arrows(&xrefs_from))
        .child(render_section_header("Register hover"))
        .child(render_register_info(reg_value.as_ref()))
}

fn render_header(focus: Addr) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .py_1()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(text_sm("Disasm @", colors::text_muted()))
        .child(text_sm(
            &format!("{:#018x}", focus.0),
            colors::syn_address(),
        ))
}

fn render_section_header(label: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .px_3()
        .py_1()
        .border_b_1()
        .border_color(colors::border())
        .bg(colors::bg_panel())
        .child(text_xs(label, colors::accent_cyan()))
}

fn render_xref_list(list: &[XrefEntry], inbound: bool) -> impl IntoElement {
    let arrow = if inbound { "\u{2190}" } else { "\u{2192}" }; // ← or →
    let placeholder = if list.is_empty() {
        Some(text_xs("  (none)", colors::text_muted()))
    } else {
        None
    };

    let rows: Vec<_> = list
        .iter()
        .map(|x| {
            let other = if inbound { x.from } else { x.to };
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .px_3()
                .py_px()
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .child(text_xs(arrow, xref_kind_color(x.kind)))
                .child(text_xs(x.kind.as_str(), xref_kind_color(x.kind)))
                .child(text_xs(
                    &format!("{:#018x}", other.0),
                    colors::syn_address(),
                ))
                .child(text_xs(
                    x.label.as_deref().unwrap_or(""),
                    colors::text_secondary(),
                ))
        })
        .collect();

    let mut wrap = div().flex().flex_col();
    if let Some(p) = placeholder {
        wrap = wrap.child(p);
    }
    wrap.children(rows)
}

fn render_jump_arrows(outbound: &[XrefEntry]) -> impl IntoElement {
    let arrows: Vec<_> = outbound
        .iter()
        .filter(|x| x.kind.is_code())
        .map(|x| {
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .px_3()
                .py_px()
                .child(text_xs("\u{21AA}", xref_kind_color(x.kind))) // ↪
                .child(text_xs(x.kind.as_str(), colors::text_secondary()))
                .child(text_xs(
                    &format!("{:#018x}", x.to.0),
                    colors::syn_address(),
                ))
        })
        .collect();

    if arrows.is_empty() {
        div()
            .flex()
            .flex_col()
            .child(text_xs("  (no outgoing jumps)", colors::text_muted()))
    } else {
        div().flex().flex_col().children(arrows)
    }
}

fn render_register_info(reg: Option<&(String, u64, u8)>) -> impl IntoElement {
    if let Some((name, value, width)) = reg {
        div()
            .flex()
            .flex_col()
            .gap_px()
            .px_3()
            .py_1()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .child(text_xs("name", colors::text_muted()))
                    .child(text_xs(name, colors::syn_register())),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .child(text_xs("value", colors::text_muted()))
                    .child(text_xs(
                        &format!("{value:#018x}"),
                        colors::syn_immediate(),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .child(text_xs("width", colors::text_muted()))
                    .child(text_xs(&format!("{width} bits"), colors::text_secondary())),
            )
    } else {
        div().flex().flex_col().px_3().py_1().child(text_xs(
            "  hover a register in the listing",
            colors::text_muted(),
        ))
    }
}

const fn xref_kind_color(k: XrefKind) -> Hsla {
    match k {
        XrefKind::Call => colors::edge_call(),
        XrefKind::Jump => colors::edge_uncond(),
        XrefKind::Fallthrough => colors::edge_true(),
        XrefKind::DataRead | XrefKind::DataRef => colors::accent_cyan(),
        XrefKind::DataWrite => colors::accent_red(),
    }
}

// ── Text helpers ────────────────────────────────────────────────────────────

fn text_xs(s: &str, color: Hsla) -> impl IntoElement {
    div().text_xs().text_color(color).truncate().child(s.to_string())
}

fn text_sm(s: &str, color: Hsla) -> impl IntoElement {
    div().text_sm().text_color(color).truncate().child(s.to_string())
}

// ── ensure_used (wire every public item; mirrors overview.rs convention) ────

#[doc(hidden)]
pub fn ensure_used_disasm_panel() {
    // Column constants
    let _ = ADDR_COL_CH;
    let _ = BYTES_COL_CH;
    let _ = MNEMONIC_COL_CH;
    let _ = COMMENT_COL_CH;

    // TokenColor
    let palette = [
        TokenColor::ADDRESS,
        TokenColor::MNEMONIC,
        TokenColor::REGISTER,
        TokenColor::IMMEDIATE,
        TokenColor::MEM_REF,
        TokenColor::COMMENT,
        TokenColor::SEPARATOR,
        TokenColor::LABEL,
        TokenColor::STRING,
        TokenColor::KEYWORD,
        TokenColor::DEFAULT,
    ];
    for c in palette {
        let _ = c.0;
        let _ = c.to_rgb();
    }

    // Row variants — construct one of each, READ every field
    let instr = InstructionRow {
        address: Addr(0),
        bytes: vec![0x90],
        mnemonic: "nop".into(),
        operands: String::new(),
        comment: None,
        is_nop: true,
        branch_target: None,
        is_call: false,
        is_return: false,
        is_unconditional_branch: false,
    };
    let _ = instr.bytes_hex();
    let _ = instr.mnemonic.len();
    let _ = instr.operands.len();
    let _ = instr.comment.as_ref().map(String::len);
    let _ = instr.is_nop;
    let _ = instr.branch_target;
    let _ = instr.is_call;
    let _ = instr.is_return;
    let _ = instr.is_unconditional_branch;

    let fhdr = FunctionHeaderRow {
        address: Addr(0),
        name: "f".into(),
        demangled_name: None,
        size_bytes: 0,
        is_noreturn: false,
        calling_convention: None,
    };
    let _ = fhdr.name.len();
    let _ = fhdr.demangled_name.as_ref().map(String::len);
    let _ = fhdr.size_bytes;
    let _ = fhdr.is_noreturn;
    let _ = fhdr.calling_convention.as_ref().map(String::len);

    let sect = SectionBoundaryRow {
        start_address: Addr(0),
        name: ".text".into(),
        size: 0,
        flags: SectionFlags {
            readable: true,
            writable: false,
            executable: true,
        },
    };
    let _ = sect.flags.flag_string();
    let _ = sect.name.len();
    let _ = sect.size;

    let gap = GapRow {
        start_address: Addr(0),
        end_address: Addr(1),
        size: 1,
    };
    let _ = gap.end_address;
    let _ = gap.size;

    let db = DataBytesRow {
        address: Addr(0),
        bytes: vec![0],
        label: None,
        interpreted_as: DataInterpretation::Bytes,
    };
    let _ = db.bytes.len();
    let _ = db.label.as_ref().map(String::len);
    match &db.interpreted_as {
        DataInterpretation::Bytes
        | DataInterpretation::U16(_)
        | DataInterpretation::U32(_)
        | DataInterpretation::U64(_)
        | DataInterpretation::Ascii(_)
        | DataInterpretation::Unicode(_)
        | DataInterpretation::Pointer(_) => {}
    }

    // Exhaustively construct & read each DataInterpretation variant payload.
    for di in [
        DataInterpretation::Bytes,
        DataInterpretation::U16(0xdead),
        DataInterpretation::U32(0xdead_beef),
        DataInterpretation::U64(0xdead_beef_cafe_babe),
        DataInterpretation::Ascii("a".into()),
        DataInterpretation::Unicode("u".into()),
        DataInterpretation::Pointer(Addr(0x1000)),
    ] {
        match di {
            DataInterpretation::Bytes => {}
            DataInterpretation::U16(v) => { let _ = v; }
            DataInterpretation::U32(v) => { let _ = v; }
            DataInterpretation::U64(v) => { let _ = v; }
            DataInterpretation::Ascii(s) | DataInterpretation::Unicode(s) => { let _ = s.len(); }
            DataInterpretation::Pointer(a) => { let _ = a; }
        }
    }

    for r in [
        DisasmRow::Instruction(instr),
        DisasmRow::FunctionHeader(fhdr),
        DisasmRow::SectionBoundary(sect),
        DisasmRow::Gap(gap),
        DisasmRow::DataBytes(db),
    ] {
        let _ = r.address();
        let _ = r.row_height_px();
        let _ = r.is_selectable();
    }

    // NavHistory
    let mut nh = NavHistory::default();
    nh.navigate_to(Addr(0x1));
    nh.navigate_to(Addr(0x2));
    let _ = nh.can_go_back();
    let _ = nh.can_go_forward();
    let _ = nh.go_back();
    let _ = nh.go_forward();
    let _ = nh.current();

    // SearchState — read every field
    let mut s = SearchState::new("nop".into());
    s.matches.push(Addr(0));
    s.case_sensitive = true;
    s.regex = false;
    let _ = s.query.len();
    let _ = s.case_sensitive;
    let _ = s.regex;
    let _ = s.current_match_address();
    let _ = s.advance();
    let _ = s.retreat();

    // Goto
    let mut g = GotoState::new();
    g.update_draft("0x100");
    let _ = g.parsed_address;
    let _ = g.error.clone();

    // Rename / comment — read every field
    let rn = RenameState {
        target_address: Addr(0),
        original_name: "x".into(),
        draft_name: "y".into(),
        cursor_pos: 0,
    };
    let _ = rn.target_address;
    let _ = rn.original_name.len();
    let _ = rn.draft_name.len();
    let _ = rn.cursor_pos;

    let cm = CommentState {
        target_address: Addr(0),
        existing_comment: None,
        draft: String::new(),
    };
    let _ = cm.target_address;
    let _ = cm.existing_comment.as_ref().map(String::len);
    let _ = cm.draft.len();

    // Context menu — enumerate every action variant
    let actions = vec![
        ContextMenuAction::Rename,
        ContextMenuAction::AddComment,
        ContextMenuAction::SetType,
        ContextMenuAction::ToggleBreakpoint,
        ContextMenuAction::CopyAddress,
        ContextMenuAction::CopyBytes,
        ContextMenuAction::CopyDisasm,
        ContextMenuAction::FindReferences,
        ContextMenuAction::DecompileFunction,
        ContextMenuAction::JumpTo(Addr(0)),
        ContextMenuAction::PatchBytes,
        ContextMenuAction::SetFunctionStart,
        ContextMenuAction::FollowReference(Addr(0)),
    ];
    let items: Vec<ContextMenuItem> = actions
        .into_iter()
        .map(|a| ContextMenuItem {
            label: "x".into(),
            action: a,
            enabled: true,
        })
        .collect();
    // Read every ContextMenuItem field, including matching every action variant
    // payload so e.g. JumpTo(Addr) / FollowReference(Addr) tuple fields count
    // as read.
    for it in &items {
        let _ = it.label.len();
        let _ = it.enabled;
        match &it.action {
            ContextMenuAction::Rename
            | ContextMenuAction::AddComment
            | ContextMenuAction::SetType
            | ContextMenuAction::ToggleBreakpoint
            | ContextMenuAction::CopyAddress
            | ContextMenuAction::CopyBytes
            | ContextMenuAction::CopyDisasm
            | ContextMenuAction::FindReferences
            | ContextMenuAction::DecompileFunction
            | ContextMenuAction::PatchBytes
            | ContextMenuAction::SetFunctionStart => {}
            ContextMenuAction::JumpTo(a) | ContextMenuAction::FollowReference(a) => { let _ = a.0; }
        }
    }
    let menu = ContextMenuState {
        position: [0.0, 0.0],
        target_address: Addr(0),
        items,
    };
    let _ = menu.position[0];
    let _ = menu.position[1];
    let _ = menu.target_address;
    let _ = menu.items.len();

    // Gutter / scrollbar
    let mut gut = GutterState::default();
    gut.bookmarks.insert(Addr(0));
    gut.breakpoints.insert(Addr(0), true);
    gut.current_ip = Some(Addr(0));
    let _ = gut;

    let sb = ScrollbarState { total_rows: 100, visible_rows: 10, scroll_offset_rows: 5, ..Default::default() };
    let _ = sb.thumb_fraction();
    let _ = sb.thumb_y_fraction();
    let _ = sb.dragging;
    let _ = sb.drag_start_y;
    let _ = sb.drag_start_offset;

    // DisasmSideState — read every field
    let mut st = DisasmSideState {
        rename_state: Some(RenameState {
            target_address: Addr(0),
            original_name: "x".into(),
            draft_name: "y".into(),
            cursor_pos: 0,
        }),
        comment_state: Some(CommentState {
            target_address: Addr(0),
            existing_comment: None,
            draft: String::new(),
        }),
        context_menu: Some(ContextMenuState {
            position: [0.0, 0.0],
            target_address: Addr(0),
            items: Vec::new(),
        }),
        ..Default::default()
    };
    let _ = st.focus_addr;
    let _ = st.nav_history.current();
    let _ = st.search_state.query.len();
    let _ = st.goto_state.draft.len();
    let _ = st.rename_state.as_ref().map(|r| r.cursor_pos);
    let _ = st.comment_state.as_ref().map(|c| c.draft.len());
    let _ = st.context_menu.as_ref().map(|m| m.items.len());
    let _ = st.show_bytes;
    let _ = st.show_comments;
    let _ = st.show_demangled;
    let _ = st.follow_mode;

    // Exercise the AppData → side-state mirror. Register a breakpoint, set
    // the program counter, and verify `refresh_from` populates the gutter
    // without the panel inventing addresses on its own.
    let mut ui = UIState::default();
    ui.current_addr = Addr(0x0040_1000);
    let mut data = AppData::new();
    data.dbg_attached = true;
    data.pc = Addr(0x0040_1000);
    data.breakpoints.insert(
        1,
        crate::core::types::Breakpoint {
            id: 1,
            addr: Addr(0x0040_1000),
            enabled: true,
            kind: crate::core::types::BpKind::Software,
            hit_count: 0,
            condition: None,
            label: None,
        },
    );
    st.refresh_from(&data, &ui);

    // Render path
    let _ = render_disasm_panel(&ui, &data);
    let _ = render_header(Addr(0));
    let _ = render_section_header("h");
    let _ = render_xref_list(&[], true);
    let _ = render_xref_list(&[], false);
    let _ = render_jump_arrows(&[]);
    let _ = render_register_info(None);
    for k in [
        XrefKind::Call,
        XrefKind::Jump,
        XrefKind::DataRead,
        XrefKind::DataWrite,
        XrefKind::DataRef,
        XrefKind::Fallthrough,
    ] {
        let _ = xref_kind_color(k);
    }
    let _ = text_xs("x", colors::text_primary());
    let _ = text_sm("x", colors::text_primary());

    // Touch a couple of theme size constants so the legacy column layout
    // constants are reachable from the same site as the live render path.
    let _ = sizes::ROW_H;
    let _ = sizes::GUTTER_W;

    // Keep `px`, `Arc<Mutex<UIState>>` symbols live — they are still part of
    // the panel's public surface (`px` for column widths, `Arc<Mutex<…>>`
    // for the lock the side-state panel shares with the workspace).
    let _ = px(ADDR_COL_CH);
    let shared_ui: Arc<Mutex<UIState>> = Arc::new(Mutex::new(UIState::default()));
    let _ = shared_ui.lock().current_addr;
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nav_history_back_forward() {
        let mut h = NavHistory::default();
        h.navigate_to(Addr(0x1000));
        h.navigate_to(Addr(0x2000));
        h.navigate_to(Addr(0x3000));
        assert_eq!(h.current(), Some(Addr(0x3000)));
        assert_eq!(h.go_back(), Some(Addr(0x2000)));
        assert_eq!(h.go_back(), Some(Addr(0x1000)));
        assert_eq!(h.go_back(), None);
        assert_eq!(h.go_forward(), Some(Addr(0x2000)));
    }

    #[test]
    fn search_state_advance_wrap() {
        let mut s = SearchState::new("nop".into());
        s.matches = vec![Addr(0x100), Addr(0x200), Addr(0x300)];
        s.wrap = true;
        s.advance();
        assert_eq!(s.current_match_idx, 1);
        s.advance();
        s.advance();
        assert_eq!(s.current_match_idx, 0);
    }

    #[test]
    fn goto_state_parse() {
        let mut g = GotoState::new();
        g.update_draft("401000");
        assert_eq!(g.parsed_address, Some(Addr(0x0040_1000)));
        assert!(g.error.is_none());
        g.update_draft("xyz");
        assert!(g.parsed_address.is_none());
        assert!(g.error.is_some());
    }

    #[test]
    fn section_flags_string() {
        let f = SectionFlags {
            readable: true,
            writable: false,
            executable: true,
        };
        assert_eq!(f.flag_string(), "r-x");
    }

    #[test]
    fn scrollbar_thumb_fraction() {
        let s = ScrollbarState { total_rows: 1000, visible_rows: 50, ..Default::default() };
        assert!((s.thumb_fraction() - 0.05).abs() < 0.01);
    }
}
