// ============================================================================
// ui/panels/taint_view.rs  —  Taint analysis visualization panel
// ============================================================================

use crate::core::app_state::UIState;
use crate::core::event_bus::{EventBus, UICommand};
use gpui::{div, hsla, px, FontWeight, Hsla, IntoElement, ParentElement, Styled,
    StatefulInteractiveElement, InteractiveElement};
use parking_lot::Mutex;
use std::sync::Arc;

// ─── Taint source kind ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaintSourceKind {
    UserInput,
    NetworkInput,
    FileInput,
    EnvironmentVar,
    RegistryRead,
    SystemCall,
    Argument,
    ReturnValue,
    MemoryRead,
    Custom,
}

impl TaintSourceKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::UserInput => "User Input",
            Self::NetworkInput => "Network",
            Self::FileInput => "File",
            Self::EnvironmentVar => "Env Var",
            Self::RegistryRead => "Registry",
            Self::SystemCall => "Syscall",
            Self::Argument => "Argument",
            Self::ReturnValue => "Return",
            Self::MemoryRead => "Memory",
            Self::Custom => "Custom",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Self::UserInput => "key",
            Self::NetworkInput => "web",
            Self::FileInput => "doc",
            Self::EnvironmentVar => "$",
            Self::RegistryRead => "cfg",
            Self::SystemCall => "K",
            Self::Argument => "->",
            Self::ReturnValue => "<-",
            Self::MemoryRead => "M",
            Self::Custom => "*",
        }
    }

    pub fn color(self) -> Hsla {
        match self {
            Self::UserInput => hsla(0.0, 0.8, 0.60, 1.0),
            Self::NetworkInput => hsla(0.6, 0.7, 0.60, 1.0),
            Self::FileInput => hsla(0.11, 0.7, 0.60, 1.0),
            Self::EnvironmentVar => hsla(0.3, 0.7, 0.58, 1.0),
            Self::RegistryRead => hsla(0.75, 0.6, 0.58, 1.0),
            Self::SystemCall => hsla(0.05, 0.8, 0.60, 1.0),
            Self::Argument => hsla(0.38, 0.6, 0.60, 1.0),
            Self::ReturnValue => hsla(0.55, 0.6, 0.58, 1.0),
            Self::MemoryRead => hsla(0.15, 0.7, 0.60, 1.0),
            Self::Custom => hsla(0.5, 0.6, 0.60, 1.0),
        }
    }
}

// ─── Taint entry ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TaintSource {
    pub id: u64,
    pub addr: u64,
    pub kind: TaintSourceKind,
    pub register: Option<String>,
    pub memory_addr: Option<u64>,
    pub description: String,
    pub func_name: String,
}

#[derive(Clone, Debug)]
pub struct TaintSink {
    pub id: u64,
    pub addr: u64,
    pub kind: TaintSinkKind,
    pub description: String,
    pub func_name: String,
    pub severity: TaintSeverity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaintSinkKind {
    BufferOverflow,
    FormatString,
    CommandInjection,
    SqlInjection,
    PathTraversal,
    IntegerOverflow,
    UseAfterFree,
    DoubleFree,
    NullDeref,
    OutOfBounds,
    MemcpySink,
    SystemSink,
    PrintfSink,
    Generic,
}

impl TaintSinkKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::BufferOverflow => "Buffer Overflow",
            Self::FormatString => "Format String",
            Self::CommandInjection => "Cmd Injection",
            Self::SqlInjection => "SQL Injection",
            Self::PathTraversal => "Path Traversal",
            Self::IntegerOverflow => "Int Overflow",
            Self::UseAfterFree => "Use After Free",
            Self::DoubleFree => "Double Free",
            Self::NullDeref => "Null Deref",
            Self::OutOfBounds => "OOB Access",
            Self::MemcpySink => "memcpy sink",
            Self::SystemSink => "system() sink",
            Self::PrintfSink => "printf sink",
            Self::Generic => "Generic",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl TaintSeverity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    pub fn color(self) -> Hsla {
        match self {
            Self::Info => hsla(0.55, 0.5, 0.60, 1.0),
            Self::Low => hsla(0.38, 0.6, 0.58, 1.0),
            Self::Medium => hsla(0.11, 0.7, 0.60, 1.0),
            Self::High => hsla(0.05, 0.8, 0.60, 1.0),
            Self::Critical => hsla(0.0, 0.9, 0.60, 1.0),
        }
    }
}

// ─── A taint flow: from source -> through propagation nodes -> to sink ─────────

#[derive(Clone, Debug)]
pub struct TaintNode {
    pub addr: u64,
    pub instruction: String,
    pub register: Option<String>,
    pub memory_addr: Option<u64>,
    pub is_sanitized: bool,
    pub is_conditional: bool,
}

#[derive(Clone, Debug)]
pub struct TaintFlow {
    pub id: u64,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<TaintNode>,
    pub is_confirmed: bool,
    pub is_sanitized: bool,
    pub sanitizer_addr: Option<u64>,
    pub path_length: usize,
}

impl TaintFlow {
    pub fn new(source: TaintSource, sink: TaintSink, path: Vec<TaintNode>) -> Self {
        let path_length = path.len();
        let is_sanitized = path.iter().any(|n| n.is_sanitized);
        Self {
            id: source.id ^ sink.id,
            source,
            sink,
            path,
            is_confirmed: false,
            is_sanitized,
            sanitizer_addr: None,
            path_length,
        }
    }

    pub const fn effective_severity(&self) -> TaintSeverity {
        if self.is_sanitized {
            TaintSeverity::Info
        } else {
            self.sink.severity
        }
    }
}

// ─── Panel state ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaintViewMode {
    Flows,
    Sources,
    Sinks,
}

impl TaintViewMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Flows => "Flows",
            Self::Sources => "Sources",
            Self::Sinks => "Sinks",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaintSort {
    Severity,
    Address,
    PathLength,
}

#[derive(Clone, Debug)]
pub struct TaintViewState {
    pub flows: Vec<TaintFlow>,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub mode: TaintViewMode,
    pub sort: TaintSort,
    pub selected_flow: Option<u64>,
    pub filter_severity: Option<TaintSeverity>,
    pub show_sanitized: bool,
    pub show_unconfirmed: bool,
    pub expanded_flow: Option<u64>,
    pub filter_text: String,
}

impl Default for TaintViewState {
    fn default() -> Self {
        Self {
            flows: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            mode: TaintViewMode::Flows,
            sort: TaintSort::Severity,
            selected_flow: None,
            filter_severity: None,
            show_sanitized: false,
            show_unconfirmed: true,
            expanded_flow: None,
            filter_text: String::new(),
        }
    }
}

impl TaintViewState {
    pub fn visible_flows(&self) -> Vec<&TaintFlow> {
        let mut flows: Vec<&TaintFlow> = self
            .flows
            .iter()
            .filter(|f| {
                if !self.show_sanitized && f.is_sanitized {
                    return false;
                }
                if let Some(min_sev) = self.filter_severity {
                    if f.effective_severity() < min_sev {
                        return false;
                    }
                }
                if !self.filter_text.is_empty() {
                    let q = self.filter_text.to_lowercase();
                    let matches = f.source.description.to_lowercase().contains(&q)
                        || f.sink.description.to_lowercase().contains(&q)
                        || f.sink.kind.label().to_lowercase().contains(&q);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .collect();

        flows.sort_by(|a, b| match self.sort {
            TaintSort::Severity => b.effective_severity().cmp(&a.effective_severity()),
            TaintSort::Address => a.source.addr.cmp(&b.source.addr),
            TaintSort::PathLength => a.path_length.cmp(&b.path_length),
        });
        flows
    }

    pub fn stats(&self) -> TaintStats {
        TaintStats {
            total_flows: self.flows.len(),
            confirmed: self.flows.iter().filter(|f| f.is_confirmed).count(),
            sanitized: self.flows.iter().filter(|f| f.is_sanitized).count(),
            critical: self
                .flows
                .iter()
                .filter(|f| f.effective_severity() == TaintSeverity::Critical)
                .count(),
            high: self
                .flows
                .iter()
                .filter(|f| f.effective_severity() == TaintSeverity::High)
                .count(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TaintStats {
    pub total_flows: usize,
    pub confirmed: usize,
    pub sanitized: usize,
    pub critical: usize,
    pub high: usize,
}

// ─── Render helpers ───────────────────────────────────────────────────────────

fn severity_badge(sev: TaintSeverity) -> impl IntoElement {
    div()
        .px(px(5.0))
        .py(px(1.0))
        .rounded(px(3.0))
        .text_size(px(9.0))
        .bg(hsla(0.0, 0.0, 0.13, 1.0))
        .text_color(sev.color())
        .font_weight(FontWeight::BOLD)
        .truncate()
        .child(sev.label().to_string())
}

fn source_icon(kind: TaintSourceKind) -> impl IntoElement {
    div()
        .w(px(16.0))
        .h(px(16.0))
        .rounded_full()
        .bg(hsla(0.0, 0.0, 0.15, 1.0))
        .flex()
        .items_center()
        .justify_center()
        .text_size(px(9.0))
        .text_color(kind.color())
        .truncate()
        .child(kind.icon().to_string())
}

fn render_taint_stats(stats: &TaintStats) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(12.0))
        .bg(hsla(0.0, 0.0, 0.09, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.17, 1.0))
        .px(px(10.0))
        .py(px(4.0))
        .child(stat_chip(
            "Total",
            stats.total_flows,
            hsla(0.0, 0.0, 0.55, 1.0),
        ))
        .child(stat_chip(
            "Critical",
            stats.critical,
            hsla(0.0, 0.8, 0.60, 1.0),
        ))
        .child(stat_chip("High", stats.high, hsla(0.05, 0.8, 0.60, 1.0)))
        .child(stat_chip(
            "Sanitized",
            stats.sanitized,
            hsla(0.38, 0.6, 0.58, 1.0),
        ))
        .child(stat_chip(
            "Confirmed",
            stats.confirmed,
            hsla(0.55, 0.6, 0.55, 1.0),
        ))
}

fn stat_chip(label: &str, val: usize, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap(px(1.0))
        .child(
            div()
                .text_size(px(13.0))
                .font_weight(FontWeight::BOLD)
                .text_color(color)
                .truncate()
                .child(val.to_string()),
        )
        .child(
            div()
                .text_size(px(9.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child(label.to_string()),
        )
}

fn render_flow_row(flow: &TaintFlow, selected: bool, expanded: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let sev = flow.effective_severity();
    let left_accent: Hsla = if flow.is_sanitized {
        hsla(0.38, 0.5, 0.45, 1.0)
    } else {
        sev.color()
    };
    let flow_id = flow.id;
    let bus_select = Arc::clone(bus);
    let bus_expand = Arc::clone(bus);

    let mut row = div().flex().flex_col();

    // Main row
    let main_row = div()
        .id(("taint-flow-row", flow_id as u32))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .px(px(8.0))
        .py(px(4.0))
        .bg(if selected {
            hsla(0.6, 0.3, 0.2, 0.4)
        } else {
            hsla(0.0, 0.0, 0.0, 0.0)
        })
        .on_click(move |_, _, cx| {
            bus_select.send_command(UICommand::TaintSelectFlow(flow_id));
            let _ = cx;
            bus_expand.send_command(UICommand::TaintToggleExpandFlow(flow_id));
        })
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.6, 0.1, 0.12, 0.4)))
        // Severity accent bar
        .child(
            div()
                .w(px(3.0))
                .h(px(28.0))
                .rounded(px(2.0))
                .bg(left_accent),
        )
        // Source icon
        .child(source_icon(flow.source.kind))
        // Source info
        .child(
            div()
                .flex()
                .flex_col()
                .w(px(180.0))
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(hsla(0.0, 0.0, 0.75, 1.0))
                        .truncate()
                        .child(flow.source.description.clone()),
                )
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(flow.source.kind.color())
                        .truncate()
                        .child(format!(
                            "{} @ {:#010x}",
                            flow.source.kind.label(),
                            flow.source.addr
                        )),
                ),
        )
        // Arrow
        .child(
            div()
                .text_size(px(14.0))
                .text_color(hsla(0.0, 0.0, 0.35, 1.0))
                .truncate()
                .child(format!("-> {} hops ->", flow.path_length)),
        )
        // Sink info
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(hsla(0.0, 0.0, 0.75, 1.0))
                        .truncate()
                        .child(flow.sink.description.clone()),
                )
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(sev.color())
                        .truncate()
                        .child(format!(
                            "{} @ {:#010x}",
                            flow.sink.kind.label(),
                            flow.sink.addr
                        )),
                ),
        )
        .child(severity_badge(sev))
        .child(if flow.is_sanitized {
            div()
                .px(px(5.0))
                .py(px(1.0))
                .rounded(px(3.0))
                .text_size(px(9.0))
                .bg(hsla(0.38, 0.3, 0.12, 1.0))
                .text_color(hsla(0.38, 0.7, 0.55, 1.0))
                .truncate()
                .child("[ok] sanitized")
                .into_any_element()
        } else {
            div().into_any_element()
        })
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.35, 1.0))
                .truncate()
                .child(if expanded { "v" } else { ">" }),
        );

    row = row.child(main_row);

    // Expanded path view
    if expanded {
        row = row.child(render_flow_path_view(flow, left_accent));
    }

    row
}

fn render_flow_path_node(i: usize, node: &TaintNode) -> impl IntoElement {
    let node_color = if node.is_sanitized {
        hsla(0.38, 0.6, 0.55, 1.0)
    } else if node.is_conditional {
        hsla(0.11, 0.6, 0.55, 1.0)
    } else {
        hsla(0.0, 0.0, 0.55, 1.0)
    };

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(hsla(0.0, 0.0, 0.30, 1.0))
                .w(px(18.0))
                .child(format!("{}", i + 1)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.6, 0.3, 0.50, 1.0))
                .w(px(80.0))
                .child(format!("{:#010x}", node.addr)),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(node_color)
                .flex_1()
                .child(node.instruction.clone()),
        )
        .child(node.register.as_ref().map_or_else(
            || div().into_any_element(),
            |reg| {
                div()
                    .px(px(4.0))
                    .rounded(px(2.0))
                    .text_size(px(9.0))
                    .bg(hsla(0.0, 0.0, 0.14, 1.0))
                    .text_color(hsla(0.05, 0.7, 0.60, 1.0))
                    .truncate()
                    .child(reg.clone())
                    .into_any_element()
            },
        ))
        .child(if node.is_sanitized {
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.38, 0.7, 0.55, 1.0))
                .truncate()
                .child("SANITIZED")
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn render_flow_path_view(flow: &TaintFlow, left_accent: Hsla) -> impl IntoElement {
    let mut path_view = div()
        .flex()
        .flex_col()
        .bg(hsla(0.0, 0.0, 0.06, 1.0))
        .border_l_2()
        .border_color(left_accent)
        .ml(px(16.0))
        .pl(px(12.0))
        .py(px(4.0))
        .gap(px(2.0));

    for (i, node) in flow.path.iter().enumerate() {
        path_view = path_view.child(render_flow_path_node(i, node));
    }
    path_view
}

fn render_source_row(src: &TaintSource, bus: &Arc<EventBus>) -> impl IntoElement {
    let src_id = src.id;
    let bus = Arc::clone(bus);
    div()
        .id(("taint-source-row", src_id as u32))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .px(px(10.0))
        .py(px(4.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.13, 1.0))
        .on_click(move |_, _, _| bus.send_command(UICommand::TaintSelectSource(src_id)))
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.0, 0.0, 0.10, 1.0)))
        .child(source_icon(src.kind))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(src.kind.color())
                .w(px(80.0))
                .child(src.kind.label().to_string()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.6, 0.3, 0.50, 1.0))
                .w(px(90.0))
                .child(format!("{:#010x}", src.addr)),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.70, 1.0))
                .flex_1()
                .child(src.description.clone()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.40, 1.0))
                .truncate()
                .child(src.func_name.clone()),
        )
}

fn render_sink_row(sink: &TaintSink, bus: &Arc<EventBus>) -> impl IntoElement {
    let sink_id = sink.id;
    let bus = Arc::clone(bus);
    div()
        .id(("taint-sink-row", sink_id as u32))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .px(px(10.0))
        .py(px(4.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.13, 1.0))
        .on_click(move |_, _, _| bus.send_command(UICommand::TaintSelectSink(sink_id)))
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.0, 0.0, 0.10, 1.0)))
        .child(severity_badge(sink.severity))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(sink.severity.color())
                .w(px(110.0))
                .child(sink.kind.label().to_string()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.6, 0.3, 0.50, 1.0))
                .w(px(90.0))
                .child(format!("{:#010x}", sink.addr)),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.70, 1.0))
                .flex_1()
                .child(sink.description.clone()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.40, 1.0))
                .truncate()
                .child(sink.func_name.clone()),
        )
}

fn render_toolbar(state: &TaintViewState, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .bg(hsla(0.0, 0.0, 0.10, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.18, 1.0))
        .px(px(8.0))
        .py(px(4.0))
        .child(mode_btn("Flows", state.mode == TaintViewMode::Flows, 0, bus))
        .child(mode_btn("Sources", state.mode == TaintViewMode::Sources, 1, bus))
        .child(mode_btn("Sinks", state.mode == TaintViewMode::Sinks, 2, bus))
        .child(
            div()
                .w(px(1.0))
                .h(px(14.0))
                .bg(hsla(0.0, 0.0, 0.22, 1.0))
                .mx(px(4.0)),
        )
        // Severity filter chips
        .child(sev_filter_btn("All", state.filter_severity.is_none(), 0, bus))
        .child(sev_filter_btn(
            "Crit",
            state.filter_severity == Some(TaintSeverity::Critical),
            1,
            bus,
        ))
        .child(sev_filter_btn(
            "High",
            state.filter_severity == Some(TaintSeverity::High),
            2,
            bus,
        ))
        .child(div().flex_1())
        .child(toggle_btn("Sanitized", state.show_sanitized, bus))
        // Sort
        .child(
            div()
                .w(px(1.0))
                .h(px(14.0))
                .bg(hsla(0.0, 0.0, 0.22, 1.0))
                .mx(px(4.0)),
        )
        .child(sort_btn("Sev", state.sort == TaintSort::Severity, 0, bus))
        .child(sort_btn("Addr", state.sort == TaintSort::Address, 1, bus))
        .child(sort_btn("Path", state.sort == TaintSort::PathLength, 2, bus))
}

fn mode_btn(label: &str, active: bool, mode_id: u8, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(("taint-mode-btn", mode_id as u32))
        .px(px(8.0))
        .py(px(2.0))
        .rounded(px(3.0))
        .text_size(px(11.0))
        .bg(if active {
            hsla(0.6, 0.4, 0.25, 1.0)
        } else {
            hsla(0.0, 0.0, 0.16, 1.0)
        })
        .text_color(if active {
            hsla(0.6, 0.8, 0.85, 1.0)
        } else {
            hsla(0.0, 0.0, 0.55, 1.0)
        })
        .on_click(move |_, _, _| bus.send_command(UICommand::TaintSetMode(mode_id)))
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.6, 0.2, 0.22, 1.0)))
        .child(label.to_string())
}

fn sev_filter_btn(label: &str, active: bool, slot: u8, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(("taint-sev-btn", slot as u32))
        .px(px(6.0))
        .py(px(2.0))
        .rounded(px(3.0))
        .text_size(px(10.0))
        .bg(if active {
            hsla(0.0, 0.4, 0.22, 1.0)
        } else {
            hsla(0.0, 0.0, 0.14, 1.0)
        })
        .text_color(if active {
            hsla(0.0, 0.8, 0.75, 1.0)
        } else {
            hsla(0.0, 0.0, 0.45, 1.0)
        })
        .on_click(move |_, _, _| {
            if slot == 0 {
                bus.send_command(UICommand::TaintClearSevFilter);
            } else {
                bus.send_command(UICommand::TaintSetSevFilter(slot));
            }
        })
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.0, 0.3, 0.20, 1.0)))
        .child(label.to_string())
}

fn sort_btn(label: &str, active: bool, slot: u8, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(("taint-sort-btn", slot as u32))
        .px(px(6.0))
        .py(px(2.0))
        .rounded(px(3.0))
        .text_size(px(10.0))
        .bg(if active {
            hsla(0.55, 0.3, 0.22, 1.0)
        } else {
            hsla(0.0, 0.0, 0.13, 1.0)
        })
        .text_color(if active {
            hsla(0.55, 0.7, 0.75, 1.0)
        } else {
            hsla(0.0, 0.0, 0.42, 1.0)
        })
        .on_click(move |_, _, _| bus.send_command(UICommand::TaintSetSort(slot)))
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.55, 0.2, 0.20, 1.0)))
        .child(label.to_string())
}

fn toggle_btn(label: &str, active: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id("taint-toggle-sanitized")
        .px(px(6.0))
        .py(px(2.0))
        .rounded(px(3.0))
        .text_size(px(10.0))
        .bg(hsla(0.0, 0.0, 0.13, 1.0))
        .text_color(if active {
            hsla(0.38, 0.7, 0.65, 1.0)
        } else {
            hsla(0.0, 0.0, 0.38, 1.0)
        })
        .on_click(move |_, _, _| bus.send_command(UICommand::TaintToggleSanitized))
        .cursor_pointer()
        .hover(|s| s.bg(hsla(0.0, 0.0, 0.18, 1.0)))
        .child(label.to_string())
}

fn render_empty_state() -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .flex_1()
        .gap(px(10.0))
        .child(
            div()
                .text_size(px(30.0))
                .text_color(hsla(0.0, 0.0, 0.20, 1.0))
                .truncate()
                .child("⊘"),
        )
        .child(
            div()
                .text_size(px(13.0))
                .text_color(hsla(0.0, 0.0, 0.32, 1.0))
                .truncate()
                .child("No taint flows"),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.25, 1.0))
                .truncate()
                .child("Run taint analysis to find data flows"),
        )
}

// ─── Main render ─────────────────────────────────────────────────────────────

fn render_taint_header(summary: &TaintStats) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .bg(hsla(0.0, 0.0, 0.11, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.19, 1.0))
        .px(px(10.0))
        .py(px(4.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.45, 1.0))
                .truncate()
                .child("TAINT ANALYSIS"),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.35, 1.0))
                .truncate()
                .child(format!("{} flows", summary.total_flows)),
        )
}

fn render_taint_status_bar(summary: &TaintStats) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .bg(hsla(0.0, 0.0, 0.07, 1.0))
        .border_t_1()
        .border_color(hsla(0.0, 0.0, 0.16, 1.0))
        .px(px(10.0))
        .py(px(3.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.8, 0.55, 1.0))
                .truncate()
                .child(format!("{} critical", summary.critical)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.05, 0.7, 0.55, 1.0))
                .truncate()
                .child(format!("{} high", summary.high)),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.38, 0.6, 0.52, 1.0))
                .truncate()
                .child(format!("{} sanitized", summary.sanitized)),
        )
}

fn render_taint_body(state: &TaintViewState, visible_flows: &[&TaintFlow], bus: &Arc<EventBus>) -> gpui::AnyElement {
    match state.mode {
        TaintViewMode::Flows => {
            if visible_flows.is_empty() {
                render_empty_state().into_any_element()
            } else {
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .overflow_hidden()
                    .children(visible_flows.iter().map({
                        let bus = Arc::clone(bus);
                        move |flow| {
                            let selected = state.selected_flow == Some(flow.id);
                            let expanded = state.expanded_flow == Some(flow.id);
                            render_flow_row(flow, selected, expanded, &bus)
                        }
                    }))
                    .into_any_element()
            }
        }
        TaintViewMode::Sources => {
            if state.sources.is_empty() {
                render_empty_state().into_any_element()
            } else {
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .overflow_hidden()
                    .children(state.sources.iter().map({
                        let bus = Arc::clone(bus);
                        move |src| render_source_row(src, &bus)
                    }))
                    .into_any_element()
            }
        }
        TaintViewMode::Sinks => {
            if state.sinks.is_empty() {
                render_empty_state().into_any_element()
            } else {
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .overflow_hidden()
                    .children(state.sinks.iter().map({
                        let bus = Arc::clone(bus);
                        move |sink| render_sink_row(sink, &bus)
                    }))
                    .into_any_element()
            }
        }
    }
}

pub fn render_taint_view(state: &TaintViewState, _ui: Arc<Mutex<UIState>>, bus: &Arc<EventBus>) -> impl IntoElement {
    let summary = state.stats();
    let visible_flows = state.visible_flows();

    div()
        .flex()
        .flex_col()
        .size_full()
        .bg(hsla(0.0, 0.0, 0.08, 1.0))
        .font_family("JetBrains Mono")
        .child(render_taint_header(&summary))
        .child(render_taint_stats(&summary))
        .child(render_toolbar(state, bus))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .child(render_taint_body(state, &visible_flows, bus)),
        )
        .child(render_taint_status_bar(&summary))
}

// ─── ensure_used scaffolding (placed before tests) ───────────────────────────

#[doc(hidden)]
pub fn ensure_used_taint_view() {
    ensure_used_taint_view_impl();
}

fn ensure_used_taint_view_kinds() {
    let src_kinds = [
        TaintSourceKind::UserInput,
        TaintSourceKind::NetworkInput,
        TaintSourceKind::FileInput,
        TaintSourceKind::EnvironmentVar,
        TaintSourceKind::RegistryRead,
        TaintSourceKind::SystemCall,
        TaintSourceKind::Argument,
        TaintSourceKind::ReturnValue,
        TaintSourceKind::MemoryRead,
        TaintSourceKind::Custom,
    ];
    for k in src_kinds {
        assert!(!k.label().is_empty());
        assert!(!k.icon().is_empty());
        let _c = k.color();
        match k {
            TaintSourceKind::UserInput
            | TaintSourceKind::NetworkInput
            | TaintSourceKind::FileInput
            | TaintSourceKind::EnvironmentVar
            | TaintSourceKind::RegistryRead
            | TaintSourceKind::SystemCall
            | TaintSourceKind::Argument
            | TaintSourceKind::ReturnValue
            | TaintSourceKind::MemoryRead
            | TaintSourceKind::Custom => {}
        }
    }

    let sink_kinds = [
        TaintSinkKind::BufferOverflow,
        TaintSinkKind::FormatString,
        TaintSinkKind::CommandInjection,
        TaintSinkKind::SqlInjection,
        TaintSinkKind::PathTraversal,
        TaintSinkKind::IntegerOverflow,
        TaintSinkKind::UseAfterFree,
        TaintSinkKind::DoubleFree,
        TaintSinkKind::NullDeref,
        TaintSinkKind::OutOfBounds,
        TaintSinkKind::MemcpySink,
        TaintSinkKind::SystemSink,
        TaintSinkKind::PrintfSink,
        TaintSinkKind::Generic,
    ];
    for k in sink_kinds {
        assert!(!k.label().is_empty());
        match k {
            TaintSinkKind::BufferOverflow
            | TaintSinkKind::FormatString
            | TaintSinkKind::CommandInjection
            | TaintSinkKind::SqlInjection
            | TaintSinkKind::PathTraversal
            | TaintSinkKind::IntegerOverflow
            | TaintSinkKind::UseAfterFree
            | TaintSinkKind::DoubleFree
            | TaintSinkKind::NullDeref
            | TaintSinkKind::OutOfBounds
            | TaintSinkKind::MemcpySink
            | TaintSinkKind::SystemSink
            | TaintSinkKind::PrintfSink
            | TaintSinkKind::Generic => {}
        }
    }

    let sevs = [
        TaintSeverity::Info,
        TaintSeverity::Low,
        TaintSeverity::Medium,
        TaintSeverity::High,
        TaintSeverity::Critical,
    ];
    for s in sevs {
        assert!(!s.label().is_empty());
        let _c = s.color();
        match s {
            TaintSeverity::Info
            | TaintSeverity::Low
            | TaintSeverity::Medium
            | TaintSeverity::High
            | TaintSeverity::Critical => {}
        }
    }
}

fn ensure_used_taint_view_renders(state: &mut TaintViewState) {
    let _ = severity_badge(TaintSeverity::High);
    let _ = source_icon(TaintSourceKind::NetworkInput);
    let summary2 = state.stats();
    let _ = render_taint_stats(&summary2);
    let _ = stat_chip("Total", 1, hsla(0.0, 0.0, 0.5, 1.0));
    let bus_eu = std::sync::Arc::new(crate::core::event_bus::EventBus::new());
    let _ = render_flow_row(&state.flows[0], true, false, &bus_eu);
    let _ = render_source_row(&state.sources[0], &bus_eu);
    let _ = render_sink_row(&state.sinks[0], &bus_eu);
    let _ = render_toolbar(state, &bus_eu);
    let _ = mode_btn("Flows", true, 0, &bus_eu);
    let _ = sev_filter_btn("Crit", false, 1, &bus_eu);
    let _ = sort_btn("Sev", true, 0, &bus_eu);
    let _ = toggle_btn("Sanitized", false, &bus_eu);
    let _ = render_empty_state();

    let ui = std::sync::Arc::new(parking_lot::Mutex::new(
        crate::core::app_state::UIState::new(),
    ));
    let _ = render_taint_view(state, ui, &bus_eu);

    state.mode = TaintViewMode::Sources;
    let _ = state.visible_flows();
    state.mode = TaintViewMode::Sinks;
    let _ = state.visible_flows();
}

fn ensure_used_taint_view_impl() {
    // Touch every dead item; called from crate::ensure_used::touch_all().
    ensure_used_taint_view_kinds();

    // --- TaintSource / TaintSink / TaintNode / TaintFlow construction ---
    let source = TaintSource {
        id: 1,
        addr: 0x4010_0000,
        kind: TaintSourceKind::NetworkInput,
        register: Some("rdi".to_string()),
        memory_addr: Some(0x7fff_0000),
        description: "recv buf".to_string(),
        func_name: "handler".to_string(),
    };
    let sink = TaintSink {
        id: 2,
        addr: 0x4020_0000,
        kind: TaintSinkKind::BufferOverflow,
        description: "memcpy".to_string(),
        func_name: "copy".to_string(),
        severity: TaintSeverity::Critical,
    };
    let node = TaintNode {
        addr: 0x4015_0000,
        instruction: "mov rax, [rdi]".to_string(),
        register: Some("rax".to_string()),
        memory_addr: None,
        is_sanitized: false,
        is_conditional: false,
    };
    debug_assert_eq!(node.addr, 0x4015_0000);
    debug_assert!(!node.is_sanitized && !node.is_conditional);
    debug_assert!(node.register.is_some() && node.memory_addr.is_none());
    debug_assert!(!node.instruction.is_empty());

    let flow = TaintFlow::new(source.clone(), sink.clone(), vec![node]);
    debug_assert_eq!(flow.effective_severity(), TaintSeverity::Critical);
    debug_assert_eq!(flow.path_length, 1);
    debug_assert!(!flow.is_confirmed);
    debug_assert!(flow.sanitizer_addr.is_none());
    debug_assert_eq!(flow.source.id, source.id);
    debug_assert_eq!(flow.sink.id, sink.id);

    let modes = [
        TaintViewMode::Flows,
        TaintViewMode::Sources,
        TaintViewMode::Sinks,
    ];
    for m in modes {
        assert!(!m.label().is_empty());
        match m {
            TaintViewMode::Flows | TaintViewMode::Sources | TaintViewMode::Sinks => {}
        }
    }

    for s in [
        TaintSort::Severity,
        TaintSort::Address,
        TaintSort::PathLength,
    ] {
        match s {
            TaintSort::Severity | TaintSort::Address | TaintSort::PathLength => {}
        }
    }

    let mut state = TaintViewState {
        flows: vec![flow],
        sources: vec![source],
        sinks: vec![sink],
        mode: TaintViewMode::Flows,
        sort: TaintSort::Severity,
        selected_flow: Some(0),
        filter_severity: Some(TaintSeverity::Low),
        show_sanitized: true,
        show_unconfirmed: true,
        expanded_flow: Some(0),
        filter_text: String::new(),
    };
    let visible = state.visible_flows();
    debug_assert_eq!(visible.len(), 1);
    let summary = state.stats();
    debug_assert_eq!(summary.total_flows, 1);
    debug_assert_eq!(summary.critical, 1);
    debug_assert_eq!(summary.confirmed, 0);
    debug_assert_eq!(summary.sanitized, 0);
    debug_assert_eq!(summary.high, 0);

    let _ = state.sources[0].register.clone();
    let _ = state.sources[0].memory_addr;
    let _ = state.show_unconfirmed;

    ensure_used_taint_view_renders(&mut state);
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source(id: u64) -> TaintSource {
        TaintSource {
            id,
            addr: 0x0040_1000 + id * 0x10,
            kind: TaintSourceKind::NetworkInput,
            register: Some("rdi".into()),
            memory_addr: None,
            description: format!("recv() buffer {id}"),
            func_name: "handle_packet".into(),
        }
    }

    fn make_sink(id: u64, sev: TaintSeverity) -> TaintSink {
        TaintSink {
            id,
            addr: 0x0040_2000 + id * 0x10,
            kind: TaintSinkKind::BufferOverflow,
            description: format!("memcpy dst {id}"),
            func_name: "copy_data".into(),
            severity: sev,
        }
    }

    fn make_flow(id: u64, sev: TaintSeverity, sanitized: bool) -> TaintFlow {
        let mut path = vec![TaintNode {
            addr: 0x0040_1010,
            instruction: "mov rax, [rdi]".into(),
            register: Some("rax".into()),
            memory_addr: None,
            is_sanitized: false,
            is_conditional: false,
        }];
        if sanitized {
            path.push(TaintNode {
                addr: 0x0040_1020,
                instruction: "call validate_input".into(),
                register: None,
                memory_addr: None,
                is_sanitized: true,
                is_conditional: false,
            });
        }
        TaintFlow::new(make_source(id), make_sink(id, sev), path)
    }

    #[test]
    fn test_flow_severity_sanitized() {
        let flow = make_flow(1, TaintSeverity::Critical, true);
        assert_eq!(flow.effective_severity(), TaintSeverity::Info);
    }

    #[test]
    fn test_flow_severity_unsanitized() {
        let flow = make_flow(1, TaintSeverity::Critical, false);
        assert_eq!(flow.effective_severity(), TaintSeverity::Critical);
    }

    #[test]
    fn test_visible_flows_filter_sanitized() {
        let mut state = TaintViewState::default();
        state.flows.push(make_flow(1, TaintSeverity::High, true));
        state.flows.push(make_flow(2, TaintSeverity::High, false));
        state.show_sanitized = false;
        let visible = state.visible_flows();
        assert_eq!(visible.len(), 1);
    }

    #[test]
    fn test_visible_flows_severity_filter() {
        let mut state = TaintViewState::default();
        state.flows.push(make_flow(1, TaintSeverity::Low, false));
        state
            .flows
            .push(make_flow(2, TaintSeverity::Critical, false));
        state.filter_severity = Some(TaintSeverity::High);
        let visible = state.visible_flows();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].effective_severity(), TaintSeverity::Critical);
    }

    #[test]
    fn test_stats() {
        let mut state = TaintViewState::default();
        state
            .flows
            .push(make_flow(1, TaintSeverity::Critical, false));
        state.flows.push(make_flow(2, TaintSeverity::High, true));
        state.flows.push(make_flow(3, TaintSeverity::Medium, false));
        let summary = state.stats();
        assert_eq!(summary.total_flows, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.sanitized, 1);
    }

    #[test]
    fn test_sort_by_severity() {
        let mut state = TaintViewState::default();
        state.flows.push(make_flow(1, TaintSeverity::Low, false));
        state
            .flows
            .push(make_flow(2, TaintSeverity::Critical, false));
        state.flows.push(make_flow(3, TaintSeverity::High, false));
        state.sort = TaintSort::Severity;
        let visible = state.visible_flows();
        assert_eq!(visible[0].effective_severity(), TaintSeverity::Critical);
        assert_eq!(visible[1].effective_severity(), TaintSeverity::High);
    }

    #[test]
    fn test_taint_severity_ordering() {
        assert!(TaintSeverity::Critical > TaintSeverity::High);
        assert!(TaintSeverity::High > TaintSeverity::Medium);
        assert!(TaintSeverity::Low < TaintSeverity::Medium);
    }
}
