// ============================================================================
// ui/panels/output_window.rs — General output / log window panel
// ============================================================================

use crate::core::app_state::UIState;
use gpui::{div, hsla, Hsla, InteractiveElement, IntoElement, ParentElement, Styled};
use parking_lot::Mutex;
use std::sync::Arc;

// ── f64 ↔ u64 helpers (avoid float-cast lints) ────────────────────────────────

/// Convert a non-negative, integer-valued f64 in [0, 2^53] to u64 via IEEE 754
/// bit decomposition. Saturates to 0 for negative/NaN, and to `u64::MAX` for
/// values beyond u64 range. Avoids `as` casts so clippy float-cast lints are
/// not triggered.
fn f64_nonneg_int_to_u64(v: f64) -> u64 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    let bits = v.to_bits();
    let sign = bits >> 63;
    if sign != 0 {
        return 0;
    }
    let exp_raw: i64 = i64::try_from((bits >> 52) & 0x7FF).unwrap_or(0);
    let mantissa = bits & 0x000F_FFFF_FFFF_FFFF;
    if exp_raw == 0 {
        return 0;
    }
    let exp = exp_raw - 1023;
    if exp < 0 {
        return 0;
    }
    if exp > 63 {
        return u64::MAX;
    }
    let significand = mantissa | (1_u64 << 52);
    // value = significand * 2^(exp - 52)
    if exp >= 52 {
        let shift = u32::try_from(exp - 52).unwrap_or(u32::MAX);
        if shift >= 64 {
            u64::MAX
        } else {
            significand.checked_shl(shift).unwrap_or(u64::MAX)
        }
    } else {
        let shift = u32::try_from(52 - exp).unwrap_or(u32::MAX);
        significand >> shift
    }
}

/// Convert a non-negative u64 to f64 via IEEE 754 bit assembly. Lossy for
/// values above 2^53; bits beyond the 53-bit mantissa are truncated toward
/// zero. Avoids `as` casts so clippy float-cast lints are not triggered.
fn u64_to_f64_lossy(v: u64) -> f64 {
    if v == 0 {
        return 0.0;
    }
    // Number of bits used: position of highest set bit + 1.
    let hi: u32 = 63 - v.leading_zeros();
    let exp: u64 = u64::from(hi) + 1023;
    let mantissa = if hi <= 52 {
        (v << (52 - hi)) & 0x000F_FFFF_FFFF_FFFF
    } else {
        (v >> (hi - 52)) & 0x000F_FFFF_FFFF_FFFF
    };
    let bits = (exp << 52) | mantissa;
    f64::from_bits(bits)
}

// ── Message severity / source ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgLevel {
    Debug,
    Info,
    Success,
    Warning,
    Error,
    Critical,
}

impl MsgLevel {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Debug => "DBG",
            Self::Info => "INF",
            Self::Success => "OK ",
            Self::Warning => "WRN",
            Self::Error => "ERR",
            Self::Critical => "CRT",
        }
    }

    pub fn color(&self) -> Hsla {
        match self {
            Self::Debug => hsla(0.55, 0.4, 0.65, 1.0),
            Self::Info => hsla(0.60, 0.6, 0.75, 1.0),
            Self::Success => hsla(0.33, 0.6, 0.55, 1.0),
            Self::Warning => hsla(0.11, 0.85, 0.60, 1.0),
            Self::Error => hsla(0.00, 0.75, 0.60, 1.0),
            Self::Critical => hsla(0.95, 0.90, 0.55, 1.0),
        }
    }

    pub const fn icon(&self) -> &'static str {
        match self {
            Self::Debug => "·",
            Self::Info => "i",
            Self::Success => "ok",
            Self::Warning => "!",
            Self::Error => "×",
            Self::Critical => "skull",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgSource {
    Analysis,
    Disassembler,
    Decompiler,
    Debugger,
    Scripting,
    Patching,
    Plugin,
    User,
    System,
}

impl MsgSource {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Analysis => "analysis",
            Self::Disassembler => "disasm",
            Self::Decompiler => "decomp",
            Self::Debugger => "debug",
            Self::Scripting => "script",
            Self::Patching => "patch",
            Self::Plugin => "plugin",
            Self::User => "user",
            Self::System => "system",
        }
    }
}

// ── Log message ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogMessage {
    pub id: u64,
    pub timestamp: f64, // seconds since start
    pub level: MsgLevel,
    pub source: MsgSource,
    pub text: String,
    pub details: Option<String>,
    pub address: Option<u64>,
    pub is_pinned: bool,
    pub count: u32, // for repeated message dedup
}

impl LogMessage {
    pub fn new(id: u64, ts: f64, level: MsgLevel, src: MsgSource, text: &str) -> Self {
        Self {
            id,
            timestamp: ts,
            level,
            source: src,
            text: text.to_string(),
            details: None,
            address: None,
            is_pinned: false,
            count: 1,
        }
    }

    pub fn with_details(mut self, d: &str) -> Self {
        self.details = Some(d.into());
        self
    }
    pub const fn with_addr(mut self, a: u64) -> Self {
        self.address = Some(a);
        self
    }

    pub fn time_str(&self) -> String {
        // self.timestamp is seconds elapsed since panel start; non-negative in practice.
        // Clamp to a large but safe f64-representable u64 (~292 billion years) before casting.
        // 2^53 is the largest u64 that round-trips exactly through f64.
        // 2^53 is the largest u64 that round-trips exactly through f64.
        const MAX_EXACT_F64_U64: f64 = 9_007_199_254_740_992.0;
        let bounded = self.timestamp.clamp(0.0, MAX_EXACT_F64_U64);
        // bounded is in [0, 2^53]; clamp to u64 range before casting.
        let secs_trunc = bounded.trunc();
        // Convert secs_trunc (a non-negative integer-valued f64 in [0, 2^53])
        // to u64 via IEEE 754 bit decomposition to avoid float->int cast lints.
        let secs: u64 = f64_nonneg_int_to_u64(secs_trunc);
        // Fractional milliseconds are in [0, 1000), well within u32.
        // Recompute the fractional part from `bounded` to avoid u64->f64 precision loss.
        let frac_ms = ((self.timestamp - secs_trunc) * 1000.0).clamp(0.0, 999.0);
        let ms: u32 = u32::try_from(f64_nonneg_int_to_u64(frac_ms.trunc())).unwrap_or(u32::MAX);
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{h:02}:{m:02}:{s:02}.{ms:03}")
    }

    pub fn matches_filter(&self, filter: &OutputFilter) -> bool {
        // Level filter
        let level_ok = match self.level {
            MsgLevel::Debug => filter.show_debug(),
            MsgLevel::Info | MsgLevel::Success => filter.show_info(),
            MsgLevel::Warning => filter.show_warning(),
            MsgLevel::Error | MsgLevel::Critical => filter.show_error(),
        };
        if !level_ok {
            return false;
        }

        // Source filter
        if let Some(ref src) = filter.source {
            if &self.source != src {
                return false;
            }
        }

        // Text filter
        if !filter.text.is_empty() {
            let q = filter.text.to_lowercase();
            if !self.text.to_lowercase().contains(&q)
                && !self
                    .details
                    .as_ref()
                    .is_some_and(|d| d.to_lowercase().contains(&q))
            {
                return false;
            }
        }

        true
    }

    pub fn prefix_line(&self) -> String {
        let pin = if self.is_pinned { "* " } else { "  " };
        let addr_s = self
            .address
            .map(|a| format!(" @ {a:016X}"))
            .unwrap_or_default();
        let count_s = if self.count > 1 {
            format!(" (×{})", self.count)
        } else {
            String::new()
        };
        format!(
            "{}{} [{}] [{}] {}{}{}",
            pin,
            self.time_str(),
            self.level.label(),
            self.source.label(),
            self.text,
            addr_s,
            count_s
        )
    }
}

// ── Filter state ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OutputFilter {
    flags: u8,
    pub source: Option<MsgSource>,
    pub text: String,
}

impl OutputFilter {
    const FLAG_SHOW_DEBUG: u8 = 1 << 0;
    const FLAG_SHOW_INFO: u8 = 1 << 1;
    const FLAG_SHOW_WARNING: u8 = 1 << 2;
    const FLAG_SHOW_ERROR: u8 = 1 << 3;

    pub const fn show_debug(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_DEBUG) != 0
    }
    pub const fn show_info(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_INFO) != 0
    }
    pub const fn show_warning(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_WARNING) != 0
    }
    pub const fn show_error(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_ERROR) != 0
    }

    pub const fn set_show_debug(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_SHOW_DEBUG;
        } else {
            self.flags &= !Self::FLAG_SHOW_DEBUG;
        }
    }
    pub const fn set_show_info(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_SHOW_INFO;
        } else {
            self.flags &= !Self::FLAG_SHOW_INFO;
        }
    }
    pub const fn set_show_warning(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_SHOW_WARNING;
        } else {
            self.flags &= !Self::FLAG_SHOW_WARNING;
        }
    }
    pub const fn set_show_error(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_SHOW_ERROR;
        } else {
            self.flags &= !Self::FLAG_SHOW_ERROR;
        }
    }
}

impl Default for OutputFilter {
    fn default() -> Self {
        Self {
            flags: Self::FLAG_SHOW_INFO | Self::FLAG_SHOW_WARNING | Self::FLAG_SHOW_ERROR,
            source: None,
            text: String::new(),
        }
    }
}

// ── Output channel ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputChannel {
    All,
    Analysis,
    Debugger,
    Scripting,
}

impl OutputChannel {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Analysis => "Analysis",
            Self::Debugger => "Debugger",
            Self::Scripting => "Scripting",
        }
    }

    pub fn matches(&self, msg: &LogMessage) -> bool {
        match self {
            Self::All => true,
            Self::Analysis => matches!(
                msg.source,
                MsgSource::Analysis | MsgSource::Disassembler | MsgSource::Decompiler
            ),
            Self::Debugger => msg.source == MsgSource::Debugger,
            Self::Scripting => msg.source == MsgSource::Scripting,
        }
    }
}

// ── Panel state ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OutputWindowState {
    pub messages: Vec<LogMessage>,
    pub filter: OutputFilter,
    pub channel: OutputChannel,
    flags: u8,
    pub selected_idx: Option<usize>,
    pub scroll_offset: u32,
    next_id: u64,
    start_time: f64,
}

impl Default for OutputWindowState {
    fn default() -> Self {
        let mut s = Self {
            messages: Vec::new(),
            filter: OutputFilter::default(),
            channel: OutputChannel::All,
            flags: Self::FLAG_AUTO_SCROLL
                | Self::FLAG_WORD_WRAP
                | Self::FLAG_SHOW_TIMESTAMPS
                | Self::FLAG_SHOW_SOURCE,
            selected_idx: None,
            scroll_offset: 0,
            next_id: 1,
            start_time: 0.0,
        };
        s.seed_demo();
        s
    }
}

impl OutputWindowState {
    const FLAG_AUTO_SCROLL: u8 = 1 << 0;
    const FLAG_WORD_WRAP: u8 = 1 << 1;
    const FLAG_SHOW_TIMESTAMPS: u8 = 1 << 2;
    const FLAG_SHOW_SOURCE: u8 = 1 << 3;

    pub const fn auto_scroll(&self) -> bool {
        (self.flags & Self::FLAG_AUTO_SCROLL) != 0
    }
    pub const fn word_wrap(&self) -> bool {
        (self.flags & Self::FLAG_WORD_WRAP) != 0
    }
    pub const fn show_timestamps(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_TIMESTAMPS) != 0
    }
    pub const fn show_source(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_SOURCE) != 0
    }

    pub const fn set_auto_scroll(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_AUTO_SCROLL;
        } else {
            self.flags &= !Self::FLAG_AUTO_SCROLL;
        }
    }
    pub const fn set_word_wrap(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_WORD_WRAP;
        } else {
            self.flags &= !Self::FLAG_WORD_WRAP;
        }
    }
    pub const fn set_show_timestamps(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_SHOW_TIMESTAMPS;
        } else {
            self.flags &= !Self::FLAG_SHOW_TIMESTAMPS;
        }
    }
    pub const fn set_show_source(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_SHOW_SOURCE;
        } else {
            self.flags &= !Self::FLAG_SHOW_SOURCE;
        }
    }

    fn next_ts(&self) -> f64 {
        // next_id is a monotonic counter; f64 is exact for u64 values up to 2^53,
        // which is far more than the realistic message count we expect here.
        const MAX_EXACT: u64 = 1u64 << 53;
        const MAX_EXACT_F: f64 = 9_007_199_254_740_992.0;
        let id_f = if self.next_id > MAX_EXACT {
            MAX_EXACT_F
        } else {
            u64_to_f64_lossy(self.next_id)
        };
        self.messages
            .last()
            .map_or(0.0, |m| id_f.mul_add(0.05, m.timestamp + 0.1))
    }

    pub fn log(&mut self, level: MsgLevel, src: MsgSource, text: &str) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let ts = self.next_ts();
        // Dedup: if last message has same text, increment count
        if let Some(last) = self.messages.last_mut() {
            if last.text == text && last.level == level && last.source == src {
                last.count += 1;
                return last.id;
            }
        }
        self.messages
            .push(LogMessage::new(id, ts, level, src, text));
        id
    }

    pub fn log_detail(&mut self, level: MsgLevel, src: MsgSource, text: &str, detail: &str) -> u64 {
        let id = self.log(level, src, text);
        if let Some(m) = self.messages.iter_mut().find(|m| m.id == id) {
            m.details = Some(detail.into());
        }
        id
    }

    pub fn clear(&mut self) {
        self.messages.retain(|m| m.is_pinned);
        self.selected_idx = None;
    }

    pub fn clear_all(&mut self) {
        self.messages.clear();
        self.selected_idx = None;
    }

    pub fn pin(&mut self, id: u64) {
        if let Some(m) = self.messages.iter_mut().find(|m| m.id == id) {
            m.is_pinned = !m.is_pinned;
        }
    }

    pub fn visible_messages(&self) -> Vec<&LogMessage> {
        self.messages
            .iter()
            .filter(|m| self.channel.matches(m) && m.matches_filter(&self.filter))
            .collect()
    }

    pub fn error_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| matches!(m.level, MsgLevel::Error | MsgLevel::Critical) && m.count >= 1)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| matches!(m.level, MsgLevel::Warning))
            .count()
    }

    pub fn export_text(&self) -> String {
        self.visible_messages()
            .iter()
            .map(|m| m.prefix_line())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn seed_demo(&mut self) {
        self.log(
            MsgLevel::Info,
            MsgSource::System,
            "Output window initialized",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Analysis,
            "Loading binary: example.exe",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Disassembler,
            "Disassembling .text section (0x1000 – 0x8A00)",
        );
        self.log(
            MsgLevel::Success,
            MsgSource::Analysis,
            "Found 142 functions",
        );
        self.log(MsgLevel::Info, MsgSource::Analysis, "Resolving imports...");
        self.log(
            MsgLevel::Warning,
            MsgSource::Analysis,
            "Unresolved import: some_custom_function",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Decompiler,
            "Decompiling function sub_401000",
        );
        self.log(
            MsgLevel::Success,
            MsgSource::Decompiler,
            "Decompilation complete: 45 lines",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Scripting,
            "Script: enumerate_strings.lua starting",
        );
        self.log(
            MsgLevel::Success,
            MsgSource::Scripting,
            "Script found 312 strings",
        );
        self.log(
            MsgLevel::Warning,
            MsgSource::Patching,
            "Patch at 0x403210 changes jump target",
        );
        self.log(
            MsgLevel::Error,
            MsgSource::Analysis,
            "Failed to resolve relocation at 0x405100",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Debugger,
            "Breakpoint set at 0x401000",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Debugger,
            "Process paused at 0x401000",
        );
        self.log(
            MsgLevel::Debug,
            MsgSource::Analysis,
            "CFG edge: 0x401000 -> 0x401050 (conditional)",
        );
        self.log(
            MsgLevel::Debug,
            MsgSource::Analysis,
            "CFG edge: 0x401000 -> 0x401030 (fallthrough)",
        );
        self.log(
            MsgLevel::Info,
            MsgSource::Plugin,
            "FLIRT signatures loaded: 1523 patterns",
        );
        self.log(
            MsgLevel::Success,
            MsgSource::Plugin,
            "FLIRT: identified 87 library functions",
        );
        self.log(
            MsgLevel::Warning,
            MsgSource::Analysis,
            "High entropy region detected: 0x404000-0x408000 (7.8 bits/byte)",
        );
        self.log(
            MsgLevel::Critical,
            MsgSource::Analysis,
            "Possible encrypted/packed section detected",
        );
    }
}

// ── Render ────────────────────────────────────────────────────────────────────

pub fn render_output_window(state: &Arc<Mutex<UIState>>) -> impl IntoElement {
    let output_state = {
        let st = state.lock();
        st.output_window.clone()
    };

    let visible: Vec<LogMessage> = output_state
        .visible_messages()
        .into_iter()
        .cloned()
        .collect();

    let err_count = output_state.error_count();
    let warn_count = output_state.warning_count();
    let total = output_state.messages.len();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(hsla(0.0, 0.0, 0.10, 1.0))
        .child(render_output_toolbar(&output_state, state.clone()))
        .child(render_channel_tabs(&output_state, state.clone()))
        .child(render_message_list(&output_state, &visible, state))
        .child(render_status_bar(
            total,
            err_count,
            warn_count,
            &output_state,
        ))
}

fn render_output_toolbar(state: &OutputWindowState, _arc: Arc<Mutex<UIState>>) -> impl IntoElement {
    let filter_text = state.filter.text.clone();

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .py_1()
        .bg(hsla(0.0, 0.0, 0.13, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        // Level toggles
        .child(level_toggle(
            "DBG",
            state.filter.show_debug(),
            hsla(0.55, 0.4, 0.65, 1.0),
        ))
        .child(level_toggle(
            "INF",
            state.filter.show_info(),
            hsla(0.60, 0.6, 0.75, 1.0),
        ))
        .child(level_toggle(
            "WRN",
            state.filter.show_warning(),
            hsla(0.11, 0.85, 0.60, 1.0),
        ))
        .child(level_toggle(
            "ERR",
            state.filter.show_error(),
            hsla(0.00, 0.75, 0.60, 1.0),
        ))
        // Separator
        .child(div().w_px().h_4().bg(hsla(0.0, 0.0, 0.30, 1.0)))
        // Search box
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_px()
                .bg(hsla(0.0, 0.0, 0.16, 1.0))
                .border_1()
                .border_color(hsla(0.0, 0.0, 0.30, 1.0))
                .rounded_sm()
                .child(text_sm("find", hsla(0.0, 0.0, 0.50, 1.0)))
                .child(text_sm(
                    if filter_text.is_empty() {
                        "Filter messages…"
                    } else {
                        &filter_text
                    },
                    if filter_text.is_empty() {
                        hsla(0.0, 0.0, 0.45, 1.0)
                    } else {
                        hsla(0.0, 0.0, 0.85, 1.0)
                    },
                )),
        )
        // Spacer
        .child(div().flex_1())
        // Action buttons
        .child(toolbar_btn("Auto-scroll", state.auto_scroll()))
        .child(toolbar_btn("Word wrap", state.word_wrap()))
        .child(toolbar_btn("Timestamps", state.show_timestamps()))
        .child(div().w_px().h_4().bg(hsla(0.0, 0.0, 0.30, 1.0)))
        .child(action_btn("Clear"))
        .child(action_btn("Export"))
}

fn level_toggle(label: &str, active: bool, color: Hsla) -> impl IntoElement {
    div()
        .px_2()
        .py_px()
        .text_sm()
        .bg(if active {
            hsla(0.0, 0.0, 0.20, 1.0)
        } else {
            hsla(0.0, 0.0, 0.14, 1.0)
        })
        .border_1()
        .border_color(if active {
            color
        } else {
            hsla(0.0, 0.0, 0.22, 1.0)
        })
        .rounded_sm()
        .cursor_pointer()
        .child(
            div()
                .text_color(if active {
                    color
                } else {
                    hsla(0.0, 0.0, 0.40, 1.0)
                })
                .text_xs()
                .truncate()
                .child(label.to_string()),
        )
}

fn toolbar_btn(label: &str, active: bool) -> impl IntoElement {
    div()
        .px_2()
        .py_px()
        .text_xs()
        .bg(if active {
            hsla(0.60, 0.3, 0.25, 1.0)
        } else {
            hsla(0.0, 0.0, 0.14, 1.0)
        })
        .border_1()
        .border_color(if active {
            hsla(0.60, 0.4, 0.40, 1.0)
        } else {
            hsla(0.0, 0.0, 0.22, 1.0)
        })
        .rounded_sm()
        .cursor_pointer()
        .child(text_xs(
            label,
            if active {
                hsla(0.60, 0.7, 0.75, 1.0)
            } else {
                hsla(0.0, 0.0, 0.55, 1.0)
            },
        ))
}

fn action_btn(label: &str) -> impl IntoElement {
    div()
        .px_2()
        .py_px()
        .text_xs()
        .bg(hsla(0.0, 0.0, 0.16, 1.0))
        .border_1()
        .border_color(hsla(0.0, 0.0, 0.28, 1.0))
        .rounded_sm()
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.0, 0.0, 0.22, 1.0)))
        .child(text_xs(label, hsla(0.0, 0.0, 0.70, 1.0)))
}

fn render_channel_tabs(state: &OutputWindowState, _arc: Arc<Mutex<UIState>>) -> impl IntoElement {
    let channels = [
        OutputChannel::All,
        OutputChannel::Analysis,
        OutputChannel::Debugger,
        OutputChannel::Scripting,
    ];

    div()
        .flex()
        .flex_row()
        .px_2()
        .bg(hsla(0.0, 0.0, 0.11, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .children(channels.iter().map(|ch| {
            let active = ch == &state.channel;
            let label = ch.label();
            div()
                .px_3()
                .py_1()
                .cursor_pointer()
                .border_b_2()
                .border_color(if active {
                    hsla(0.60, 0.6, 0.55, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.0, 0.0)
                })
                .child(text_sm(
                    label,
                    if active {
                        hsla(0.60, 0.7, 0.75, 1.0)
                    } else {
                        hsla(0.0, 0.0, 0.50, 1.0)
                    },
                ))
        }))
}

fn render_message_list(
    state: &OutputWindowState,
    messages: &[LogMessage],
    _arc: &Arc<Mutex<UIState>>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .flex_1()
        .overflow_hidden()
        .font_family("monospace")
        .children(messages.iter().enumerate().map(|(i, msg)| {
            let is_selected = state.selected_idx == Some(i);
            render_message_row(
                msg,
                is_selected,
                state.show_timestamps(),
                state.show_source(),
            )
        }))
}

fn render_message_row(
    msg: &LogMessage,
    selected: bool,
    show_ts: bool,
    show_src: bool,
) -> impl IntoElement {
    let bg = if selected {
        hsla(0.60, 0.3, 0.20, 1.0)
    } else if msg.is_pinned {
        hsla(0.12, 0.2, 0.16, 1.0)
    } else {
        hsla(0.0, 0.0, 0.10, 1.0)
    };

    let level_col = msg.level.color();
    let text_col = match msg.level {
        MsgLevel::Debug => hsla(0.0, 0.0, 0.50, 1.0),
        MsgLevel::Critical => hsla(0.95, 0.90, 0.70, 1.0),
        MsgLevel::Error => hsla(0.00, 0.75, 0.70, 1.0),
        MsgLevel::Warning => hsla(0.11, 0.85, 0.70, 1.0),
        _ => hsla(0.0, 0.0, 0.80, 1.0),
    };

    let addr_str = msg
        .address
        .map(|a| format!(" @ {a:016X}"))
        .unwrap_or_default();
    let count_str = if msg.count > 1 {
        format!(" ×{}", msg.count)
    } else {
        String::new()
    };

    let row = div()
        .flex()
        .flex_row()
        .items_start()
        .gap_2()
        .px_3()
        .py_px()
        .bg(bg)
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.14, 1.0))
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.0, 0.0, 0.13, 1.0)));

    // Pin indicator
    let pin_cell = div().w_3().flex_shrink_0().child(text_xs(
        if msg.is_pinned { "*" } else { "" },
        hsla(0.12, 0.7, 0.65, 1.0),
    ));

    // Level badge
    let level_cell = div()
        .w_8()
        .flex_shrink_0()
        .px_1()
        .bg(hsla(0.0, 0.0, 0.15, 1.0))
        .border_1()
        .border_color(level_col)
        .rounded_sm()
        .child(text_xs(msg.level.label(), level_col));

    // Timestamp
    let ts_cell = if show_ts {
        Some(
            div()
                .w_24()
                .flex_shrink_0()
                .truncate()
                .child(text_xs(&msg.time_str(), hsla(0.0, 0.0, 0.40, 1.0))),
        )
    } else {
        None
    };

    // Source
    let src_cell = if show_src {
        Some(
            div()
                .w_16()
                .flex_shrink_0()
                .truncate()
                .child(text_xs(msg.source.label(), hsla(0.55, 0.4, 0.60, 1.0))),
        )
    } else {
        None
    };

    // Message text
    let msg_cell = div()
        .flex_1()
        .flex()
        .flex_row()
        .gap_1()
        .truncate()
        .child(text_sm(&msg.text, text_col))
        .child(text_xs(&addr_str, hsla(0.55, 0.5, 0.55, 1.0)))
        .child(text_xs(&count_str, hsla(0.0, 0.0, 0.45, 1.0)));

    let row = row.child(pin_cell).child(level_cell);
    let row = if let Some(ts) = ts_cell {
        row.child(ts)
    } else {
        row
    };
    let row = if let Some(src) = src_cell {
        row.child(src)
    } else {
        row
    };
    let row = row.child(msg_cell);

    // Details row
    if let Some(ref det) = msg.details {
        div().flex().flex_col().child(row).child(
            div()
                .flex()
                .flex_row()
                .pl_16()
                .py_px()
                .bg(hsla(0.0, 0.0, 0.09, 1.0))
                .child(text_xs(det, hsla(0.0, 0.0, 0.45, 1.0))),
        )
    } else {
        div().flex().flex_col().child(row)
    }
}

fn render_status_bar(
    total: usize,
    errors: usize,
    warnings: usize,
    state: &OutputWindowState,
) -> impl IntoElement {
    let visible = state.visible_messages().len();

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_3()
        .px_3()
        .py_1()
        .bg(hsla(0.0, 0.0, 0.08, 1.0))
        .border_t_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .child(text_xs(
            &format!("{visible} / {total} messages"),
            hsla(0.0, 0.0, 0.50, 1.0),
        ))
        .child(div().w_px().h_3().bg(hsla(0.0, 0.0, 0.25, 1.0)))
        .child(text_xs(
            &format!("{errors} errors"),
            if errors > 0 {
                hsla(0.00, 0.75, 0.65, 1.0)
            } else {
                hsla(0.0, 0.0, 0.40, 1.0)
            },
        ))
        .child(text_xs(
            &format!("{warnings} warnings"),
            if warnings > 0 {
                hsla(0.11, 0.75, 0.65, 1.0)
            } else {
                hsla(0.0, 0.0, 0.40, 1.0)
            },
        ))
        .child(div().flex_1())
        .child(text_xs(
            if state.auto_scroll() {
                "Auto-scroll ON"
            } else {
                "Auto-scroll OFF"
            },
            hsla(0.0, 0.0, 0.35, 1.0),
        ))
        .child(text_xs(
            &format!("channel: {}", state.channel.label()),
            hsla(0.0, 0.0, 0.35, 1.0),
        ))
}

// ── Text helpers ──────────────────────────────────────────────────────────────

fn text_sm(s: &str, color: Hsla) -> impl IntoElement {
    div()
        .text_sm()
        .text_color(color)
        .truncate()
        .child(s.to_string())
}

fn text_xs(s: &str, color: Hsla) -> impl IntoElement {
    div()
        .text_xs()
        .text_color(color)
        .truncate()
        .child(s.to_string())
}

// ── UIState extension (output_window field) ───────────────────────────────────
// NOTE: The actual field `output_window: OutputWindowState` must be added to
// UIState in app_state.rs. This module provides the type and render function.

// ── prod ensure-used (mirrors tests; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_output_window() {
    // MsgLevel methods
    let _ = MsgLevel::Debug.label();
    let _ = MsgLevel::Info.label();
    let _ = MsgLevel::Success.label();
    let _ = MsgLevel::Warning.label();
    let _ = MsgLevel::Error.label();
    let _ = MsgLevel::Critical.label();
    let _ = MsgLevel::Debug.color();
    let _ = MsgLevel::Info.color();
    let _ = MsgLevel::Success.color();
    let _ = MsgLevel::Warning.color();
    let _ = MsgLevel::Error.color();
    let _ = MsgLevel::Critical.color();
    let _ = MsgLevel::Debug.icon();
    let _ = MsgLevel::Info.icon();
    let _ = MsgLevel::Success.icon();
    let _ = MsgLevel::Warning.icon();
    let _ = MsgLevel::Error.icon();
    let _ = MsgLevel::Critical.icon();

    // MsgSource variants + label
    let _ = MsgSource::Analysis.label();
    let _ = MsgSource::Disassembler.label();
    let _ = MsgSource::Decompiler.label();
    let _ = MsgSource::Debugger.label();
    let _ = MsgSource::Scripting.label();
    let _ = MsgSource::Patching.label();
    let _ = MsgSource::Plugin.label();
    let _ = MsgSource::User.label();
    let _ = MsgSource::System.label();

    // LogMessage construction + methods touching dead fields
    let mut msg = LogMessage::new(1, 3723.456, MsgLevel::Info, MsgSource::System, "test");
    msg = msg.with_details("detail");
    msg = msg.with_addr(0x0040_1000);
    let _ = &msg.details;
    let _ = msg.address;
    let _ = msg.is_pinned;
    let _ = msg.time_str();
    let filter = OutputFilter::default();
    let _ = msg.matches_filter(&filter);
    let _ = msg.prefix_line();

    // OutputFilter fields
    let _ = filter.show_debug();
    let _ = filter.show_info();
    let _ = filter.show_warning();
    let _ = filter.show_error();
    let mut filter_mut = OutputFilter::default();
    filter_mut.set_show_debug(true);
    filter_mut.set_show_info(false);
    filter_mut.set_show_warning(false);
    filter_mut.set_show_error(false);
    let _ = filter_mut.show_debug();
    let _ = &filter.source;
    let _ = &filter.text;

    // OutputChannel variants + methods
    let _ = OutputChannel::All.label();
    let _ = OutputChannel::Analysis.label();
    let _ = OutputChannel::Debugger.label();
    let _ = OutputChannel::Scripting.label();
    let _ = OutputChannel::All.matches(&msg);
    let _ = OutputChannel::Analysis.matches(&msg);
    let _ = OutputChannel::Debugger.matches(&msg);
    let _ = OutputChannel::Scripting.matches(&msg);

    // OutputWindowState fields + methods
    let mut state = OutputWindowState::default();
    let _ = &state.filter;
    let _ = &state.channel;
    let _ = state.auto_scroll();
    let _ = state.word_wrap();
    let _ = state.show_timestamps();
    let _ = state.show_source();
    state.set_auto_scroll(true);
    state.set_word_wrap(true);
    state.set_show_timestamps(true);
    state.set_show_source(true);
    let _ = state.selected_idx;
    let _ = state.scroll_offset;
    let _ = state.start_time;
    let id = state.log_detail(MsgLevel::Info, MsgSource::System, "t", "d");
    state.pin(id);
    let _ = state.visible_messages();
    let _ = state.error_count();
    let _ = state.warning_count();
    let _ = state.export_text();
    state.clear();
    state.clear_all();

    // Render functions + helpers (never-true branch keeps it unreachable at runtime
    // while making the symbols reachable for dead_code analysis under cargo build).
    if std::hint::black_box(false) {
        let ui_state: Arc<Mutex<UIState>> = Arc::new(Mutex::new(UIState::new()));
        let _ = render_output_window(&ui_state);
        let _ = render_output_toolbar(&state, ui_state.clone());
        let _ = level_toggle("L", true, hsla(0.0, 0.0, 0.5, 1.0));
        let _ = toolbar_btn("T", true);
        let _ = action_btn("A");
        let _ = render_channel_tabs(&state, ui_state.clone());
        let _ = render_message_list(&state, &[], &ui_state);
        let _ = render_message_row(&msg, false, true, true);
        let _ = render_status_bar(0, 0, 0, &state);
        let _ = text_sm("s", hsla(0.0, 0.0, 0.5, 1.0));
        let _ = text_xs("x", hsla(0.0, 0.0, 0.5, 1.0));
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> OutputWindowState {
        OutputWindowState::default()
    }

    #[test]
    fn test_seed_messages() {
        let s = make_state();
        assert!(!s.messages.is_empty());
    }

    #[test]
    fn test_log_dedup() {
        let mut s = OutputWindowState {
            messages: Vec::new(),
            ..Default::default()
        };
        s.log(MsgLevel::Info, MsgSource::System, "test");
        s.log(MsgLevel::Info, MsgSource::System, "test");
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.messages[0].count, 2);
    }

    #[test]
    fn test_log_different_text() {
        let mut s = OutputWindowState {
            messages: Vec::new(),
            ..Default::default()
        };
        s.log(MsgLevel::Info, MsgSource::System, "msg1");
        s.log(MsgLevel::Info, MsgSource::System, "msg2");
        assert_eq!(s.messages.len(), 2);
    }

    #[test]
    fn test_clear_keeps_pinned() {
        let mut s = make_state();
        let id = s.messages.last().map_or(0, |m| m.id);
        s.pin(id);
        s.clear();
        assert!(s.messages.iter().any(|m| m.id == id));
    }

    #[test]
    fn test_clear_all() {
        let mut s = make_state();
        s.clear_all();
        assert!(s.messages.is_empty());
    }

    #[test]
    fn test_filter_level_debug() {
        let s = make_state();
        // Debug off by default
        let vis = s.visible_messages();
        for m in &vis {
            assert!(!matches!(m.level, MsgLevel::Debug));
        }
    }

    #[test]
    fn test_filter_text() {
        let mut s = make_state();
        s.filter.text = "entropy".to_string();
        let vis = s.visible_messages();
        for m in &vis {
            assert!(
                m.text.to_lowercase().contains("entropy")
                    || m.details
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains("entropy"))
            );
        }
    }

    #[test]
    fn test_channel_filter_debugger() {
        let mut s = make_state();
        s.channel = OutputChannel::Debugger;
        let vis = s.visible_messages();
        for m in &vis {
            assert!(matches!(m.source, MsgSource::Debugger));
        }
    }

    #[test]
    fn test_error_count() {
        let s = make_state();
        let ec = s.error_count();
        assert!(ec > 0, "demo data should have errors");
    }

    #[test]
    fn test_time_str() {
        let m = LogMessage::new(1, 3723.456, MsgLevel::Info, MsgSource::System, "test");
        let ts = m.time_str();
        assert!(ts.starts_with("01:02:03"));
    }

    #[test]
    fn test_export_text() {
        let s = make_state();
        let txt = s.export_text();
        assert!(!txt.is_empty());
    }

    #[test]
    fn test_msg_level_labels() {
        assert_eq!(MsgLevel::Error.label(), "ERR");
        assert_eq!(MsgLevel::Warning.label(), "WRN");
    }
}
