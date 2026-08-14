// ============================================================================
// ui/panels/symb_panel.rs - Symbolic Execution & Taint Analysis panel
//
// Hosts six related views inside a single right-panel tab:
//   1. Symbolic execution runner / status
//   2. Symbolic state inspector (registers, memory, path conditions)
//   3. Path exploration / forking tree
//   4. Taint analysis runner (sources / sinks configuration)
//   5. Taint propagation graph
//   6. Taint findings table
//
// Each view consumes data already exposed by the existing `taint_view` panel
// types so we re-use the canonical TaintSource / TaintSink / TaintFlow shapes.
// ============================================================================

use crate::core::app_state::UIState;
use crate::core::event_bus::{EventBus, UICommand};
use crate::ui::panels::taint_view::{
    TaintFlow, TaintNode, TaintSeverity, TaintSink, TaintSinkKind, TaintSource, TaintSourceKind,
};
use crate::ui::theme::colors;
use crate::ui::widgets::icon::{icon_colored, icon_sized};
use gpui::{div, px, FontWeight, IntoElement, ParentElement, Styled, StatefulInteractiveElement, InteractiveElement};
use parking_lot::Mutex;
use std::sync::Arc;

// ─── Sub-mode ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbMode {
    Run,
    State,
    Paths,
    TaintConfig,
    TaintGraph,
    TaintFindings,
}

impl SymbMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Run => "Run",
            Self::State => "State",
            Self::Paths => "Paths",
            Self::TaintConfig => "Taint Cfg",
            Self::TaintGraph => "Taint Graph",
            Self::TaintFindings => "Findings",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Run => "play",
            Self::State => "sigma",
            Self::Paths => "git-branch",
            Self::TaintConfig => "settings",
            Self::TaintGraph => "share-2",
            Self::TaintFindings => "bug",
        }
    }
}

// ─── Symbolic state snapshot ─────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SymRegister {
    pub name: String,
    pub expr: String,
    pub concrete: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct SymMemCell {
    pub addr: u64,
    pub width: u32,
    pub expr: String,
}

#[derive(Clone, Debug, Default)]
pub struct SymPathCond {
    pub addr: u64,
    pub expr: String,
    pub taken: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SymStateSnapshot {
    pub step: u64,
    pub pc: u64,
    pub registers: Vec<SymRegister>,
    pub memory: Vec<SymMemCell>,
    pub path_conditions: Vec<SymPathCond>,
}

// ─── Path exploration tree ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SymPathNode {
    pub id: u64,
    pub parent: Option<u64>,
    pub addr: u64,
    pub condition: String,
    pub feasible: bool,
    pub completed: bool,
    pub depth: u32,
}

// ─── Taint runner configuration ──────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TaintSourceSpec {
    pub kind: TaintSourceKind,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct TaintSinkSpec {
    pub kind: TaintSinkKind,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct TaintRunConfig {
    pub sources: Vec<TaintSourceSpec>,
    pub sinks: Vec<TaintSinkSpec>,
    pub interprocedural: bool,
    pub max_depth: u32,
}

impl Default for TaintRunConfig {
    fn default() -> Self {
        let sources = [
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
        ]
        .into_iter()
        .map(|k| TaintSourceSpec {
            kind: k,
            enabled: true,
        })
        .collect();

        let sinks = [
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
        ]
        .into_iter()
        .map(|k| TaintSinkSpec {
            kind: k,
            enabled: true,
        })
        .collect();

        Self {
            sources,
            sinks,
            interprocedural: true,
            max_depth: 32,
        }
    }
}

// ─── Findings filter ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingFilter {
    All,
    Kind(TaintSinkKind),
    MinSeverity(TaintSeverity),
}

// ─── Panel state ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SymbPanelState {
    pub mode: SymbMode,
    pub current_func_id: Option<u32>,
    pub current_func_name: String,
    pub running: bool,
    pub progress: f32,
    pub status: String,
    pub state: SymStateSnapshot,
    pub paths: Vec<SymPathNode>,
    pub selected_path: Option<u64>,
    pub taint_config: TaintRunConfig,
    pub flows: Vec<TaintFlow>,
    pub findings_filter: FindingFilter,
    pub selected_flow: Option<u64>,
}

impl Default for SymbPanelState {
    fn default() -> Self {
        Self {
            mode: SymbMode::Run,
            current_func_id: None,
            current_func_name: String::new(),
            running: false,
            progress: 0.0,
            status: "Idle".to_string(),
            state: SymStateSnapshot::default(),
            paths: Vec::new(),
            selected_path: None,
            taint_config: TaintRunConfig::default(),
            flows: Vec::new(),
            findings_filter: FindingFilter::All,
            selected_flow: None,
        }
    }
}

impl SymbPanelState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refresh(
        &mut self,
        _data: &crate::core::app_state::AppData,
        _rev: u64,
        current_func_id: Option<u32>,
    ) {
        self.current_func_id = current_func_id;
    }

    pub fn set_func(&mut self, func_id: u32, name: String) {
        self.current_func_id = Some(func_id);
        self.current_func_name = name;
    }

    pub fn begin_run(&mut self, label: &str) {
        self.running = true;
        self.progress = 0.0;
        self.status = format!("Running: {label}");
    }

    pub fn finish_run(&mut self, label: &str) {
        self.running = false;
        self.progress = 1.0;
        self.status = format!("Done: {label}");
    }

    pub fn filtered_flows(&self) -> Vec<&TaintFlow> {
        self.flows
            .iter()
            .filter(|f| match self.findings_filter {
                FindingFilter::All => true,
                FindingFilter::Kind(k) => f.sink.kind == k,
                FindingFilter::MinSeverity(s) => f.effective_severity() >= s,
            })
            .collect()
    }
}

// ─── Render helpers ──────────────────────────────────────────────────────────

fn header(title: &str, state: &SymbPanelState) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .px(px(10.0))
        .py(px(4.0))
        .child(icon_colored("alembic", colors::accent()))
        .child(
            div()
                .text_size(px(12.0))
                .text_color(colors::text_bright())
                .font_weight(FontWeight::BOLD)
                .truncate()
                .child(title.to_string()),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(if state.current_func_id.is_some() {
                    format!(
                        "fn: {} (#{})",
                        state.current_func_name,
                        state.current_func_id.unwrap_or(0)
                    )
                } else {
                    "no function selected".to_string()
                }),
        )
}

fn mode_tab(mode: SymbMode, active: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    let color = if active {
        colors::accent()
    } else {
        colors::text_secondary()
    };
    div()
        .id(("symb-mode", mode as u32))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .px(px(8.0))
        .py(px(4.0))
        .rounded_sm()
.on_click(move |_, _, _| bus.send_command(UICommand::SymbSetMode(mode as u8)))
        .cursor_pointer()
        .bg(if active {
            colors::bg_selection()
        } else {
            colors::bg_surface()
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .child(icon_colored(mode.icon(), color))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(color)
                .truncate()
                .child(mode.label().to_string()),
        )
}

fn mode_bar(state: &SymbPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .px(px(6.0))
        .py(px(4.0))
        .child(mode_tab(SymbMode::Run, state.mode == SymbMode::Run, bus))
        .child(mode_tab(SymbMode::State, state.mode == SymbMode::State, bus))
        .child(mode_tab(SymbMode::Paths, state.mode == SymbMode::Paths, bus))
        .child(mode_tab(SymbMode::TaintConfig, state.mode == SymbMode::TaintConfig, bus))
        .child(mode_tab(SymbMode::TaintGraph, state.mode == SymbMode::TaintGraph, bus))
        .child(mode_tab(SymbMode::TaintFindings, state.mode == SymbMode::TaintFindings, bus))
}

fn status_strip(state: &SymbPanelState) -> impl IntoElement {
    let bar_color = if state.running {
        colors::accent_blue()
    } else {
        colors::ok()
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .bg(colors::bg_panel())
        .border_t_1()
        .border_color(colors::border())
        .px(px(10.0))
        .py(px(3.0))
        .child(
            div()
                .w(px(8.0))
                .h(px(8.0))
                .rounded_full()
                .bg(bar_color),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_secondary())
                .truncate()
                .child(state.status.clone()),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{} flows", state.flows.len())),
        )
}

// ── Run view ────────────────────────────────────────────────────────────────

fn render_run_view(state: &SymbPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let func_label = if state.current_func_id.is_some() {
        format!("Selected function: {}", state.current_func_name)
    } else {
        "No function selected. Pick a function in the Functions panel.".to_string()
    };
    div()
        .flex()
        .flex_col()
        .gap(px(10.0))
        .p(px(12.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_muted())
                .truncate()
                .child("SYMBOLIC EXECUTION"),
        )
        .child(
            div()
                .text_size(px(12.0))
                .text_color(colors::text_primary())
                .truncate()
                .child(func_label),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(6.0))
                .child(action_btn("Run on Function", "play", state.current_func_id.is_some(), UICommand::SymbRunSymbolic, bus))
                .child(action_btn("Run Taint Analysis", "bug", state.current_func_id.is_some(), UICommand::SymbRunTaint, bus))
                .child(action_btn("Stop", "square_small", state.running, UICommand::SymbStop, bus)),
        )
        .child(progress_bar(state.progress, state.running))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(colors::text_muted())
                        .truncate()
                        .child("Engine"),
                )
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(colors::text_primary())
                        .truncate()
                        .child("rustre-symb / rustre-symb-engine"),
                ),
        )
}

fn action_btn(label: &str, icon_name: &'static str, enabled: bool, cmd: UICommand, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    let label_owned = label.to_string();
    let (bg, fg) = if enabled {
        (colors::bg_elevated(), colors::text_bright())
    } else {
        (colors::bg_surface(), colors::text_muted())
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .px(px(8.0))
        .py(px(4.0))
        .rounded_sm()
        .border_1()
        .border_color(colors::border())
        .bg(bg)
        .id(gpui::SharedString::from(label_owned.clone()))
        .on_click(move |_, _, _| bus.send_command(cmd.clone()))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(icon_sized(icon_name, 12.0, 12.0))
        .child(div().text_size(px(11.0)).text_color(fg).child(label.to_string()))
}

fn progress_bar(progress: f32, running: bool) -> impl IntoElement {
    let pct = progress.clamp(0.0, 1.0);
    div()
        .w_full()
        .h(px(6.0))
        .rounded_sm()
        .bg(colors::bg_surface())
        .child(
            div()
                .h_full()
                .w(px(200.0 * pct))
                .rounded_sm()
                .bg(if running {
                    colors::accent_blue()
                } else {
                    colors::ok()
                }),
        )
}

// ── State view ──────────────────────────────────────────────────────────────

fn render_state_view(state: &SymbPanelState) -> impl IntoElement {
    let snap = &state.state;
    div()
        .flex()
        .flex_col()
        .gap(px(8.0))
        .p(px(8.0))
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(12.0))
                .child(kv("step", &snap.step.to_string()))
                .child(kv("pc", &format!("{:#010x}", snap.pc))),
        )
        .child(section_header("REGISTERS", snap.registers.len()))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .children(snap.registers.iter().map(render_register_row)),
        )
        .child(section_header("MEMORY", snap.memory.len()))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .children(snap.memory.iter().map(render_mem_row)),
        )
        .child(section_header("PATH CONDITIONS", snap.path_conditions.len()))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .children(snap.path_conditions.iter().map(render_pc_row)),
        )
}

fn kv(k: &str, v: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap(px(4.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(k.to_string()),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_bright())
                .font_family("JetBrains Mono")
                .child(v.to_string()),
        )
}

fn section_header(title: &str, count: usize) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .border_b_1()
        .border_color(colors::border())
        .pb(px(2.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::accent_cyan())
                .font_weight(FontWeight::BOLD)
                .truncate()
                .child(title.to_string()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("({count})")),
        )
}

fn render_register_row(r: &SymRegister) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap(px(8.0))
        .px(px(4.0))
        .child(
            div()
                .w(px(40.0))
                .text_size(px(11.0))
                .text_color(colors::syn_register())
                .truncate()
                .child(r.name.clone()),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .flex_1()
                .child(r.expr.clone()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(
                    r.concrete
                        .map_or_else(String::new, |c| format!("= {c:#x}")),
                ),
        )
}

fn render_mem_row(m: &SymMemCell) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap(px(8.0))
        .px(px(4.0))
        .child(
            div()
                .w(px(90.0))
                .text_size(px(11.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#010x}", m.addr)),
        )
        .child(
            div()
                .w(px(36.0))
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("[{}b]", m.width)),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .flex_1()
                .child(m.expr.clone()),
        )
}

fn render_pc_row(p: &SymPathCond) -> impl IntoElement {
    let color = if p.taken {
        colors::edge_true()
    } else {
        colors::edge_false()
    };
    div()
        .flex()
        .flex_row()
        .gap(px(8.0))
        .px(px(4.0))
        .child(
            div()
                .w(px(90.0))
                .text_size(px(11.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#010x}", p.addr)),
        )
        .child(
            div()
                .w(px(50.0))
                .text_size(px(10.0))
                .text_color(color)
                .truncate()
                .child(if p.taken { "taken" } else { "not-taken" }.to_string()),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .flex_1()
                .child(p.expr.clone()),
        )
}

// ── Paths view ──────────────────────────────────────────────────────────────

fn render_paths_view(state: &SymbPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    if state.paths.is_empty() {
        return empty_state("No path exploration data", "Run symbolic execution first")
            .into_any_element();
    }
    div()
        .flex()
        .flex_col()
        .gap(px(1.0))
        .p(px(6.0))
        .children(state.paths.iter().map({
            let bus = Arc::clone(bus);
            move |node| {
                render_path_node(node, state.selected_path == Some(node.id), &bus)
            }
        }))
        .into_any_element()
}

fn render_path_node(node: &SymPathNode, selected: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    let node_id = node.id;
    let depth_indent = px(f32::from(u16::try_from(node.depth).unwrap_or(0)) * 12.0);
    // Breadcrumb: show parent id when present so the user can trace the
    // fork chain back to the root without expanding the full path tree.
    let parent_label = node
        .parent
        .map_or_else(|| "root".to_string(), |pid| format!("↑{pid}"));
    let status_color = if !node.feasible {
        colors::err()
    } else if node.completed {
        colors::ok()
    } else {
        colors::accent_blue()
    };
    let label = if !node.feasible {
        "infeasible"
    } else if node.completed {
        "done"
    } else {
        "active"
    };
    div()
        .id(("symb-path-node", node_id as u32))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .pl(depth_indent)
        .px(px(6.0))
        .py(px(2.0))
        .rounded_sm()
        .bg(if selected {
            colors::bg_selection()
        } else {
            colors::bg_panel()
        })
        .on_click(move |_, _, _| bus.send_command(UICommand::SymbSelectPath(node_id)))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(icon_colored("git-branch", status_color))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .w(px(54.0))
                .child(label.to_string()),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::syn_address())
                .w(px(90.0))
                .child(format!("{:#010x}", node.addr)),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .flex_1()
                .child(node.condition.clone()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("#{}", node.id)),
        )
        // Breadcrumb parent link — navigating the fork chain.
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(parent_label),
        )
}

// ── Taint config view ──────────────────────────────────────────────────────

fn render_taint_config(state: &SymbPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let cfg = &state.taint_config;
    div()
        .flex()
        .flex_col()
        .gap(px(8.0))
        .p(px(8.0))
        .child(section_header("SOURCES", cfg.sources.len()))
        .child(
            div()
                .flex()
                .flex_row()
                .flex_wrap()
                .gap(px(4.0))
                .children(cfg.sources.iter().map(render_source_chip)),
        )
        .child(section_header("SINKS", cfg.sinks.len()))
        .child(
            div()
                .flex()
                .flex_row()
                .flex_wrap()
                .gap(px(4.0))
                .children(cfg.sinks.iter().map(render_sink_chip)),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(12.0))
                .child(kv("interprocedural", &cfg.interprocedural.to_string()))
                .child(kv("max depth", &cfg.max_depth.to_string())),
        )
        .child(action_btn("Run Taint Analysis", "bug", true, UICommand::SymbRunTaint, bus))
}

fn render_source_chip(spec: &TaintSourceSpec) -> impl IntoElement {
    let color = if spec.enabled {
        spec.kind.color()
    } else {
        colors::text_muted()
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .px(px(6.0))
        .py(px(2.0))
        .rounded_sm()
        .border_1()
        .border_color(colors::border())
        .bg(colors::bg_surface())
        .child(
            div()
                .w(px(6.0))
                .h(px(6.0))
                .rounded_full()
                .bg(color),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(color)
                .truncate()
                .child(spec.kind.label().to_string()),
        )
}

fn render_sink_chip(spec: &TaintSinkSpec) -> impl IntoElement {
    let color = if spec.enabled {
        colors::accent_red()
    } else {
        colors::text_muted()
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .px(px(6.0))
        .py(px(2.0))
        .rounded_sm()
        .border_1()
        .border_color(colors::border())
        .bg(colors::bg_surface())
        .child(
            div()
                .w(px(6.0))
                .h(px(6.0))
                .rounded_full()
                .bg(color),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(color)
                .truncate()
                .child(spec.kind.label().to_string()),
        )
}

// ── Taint graph view ───────────────────────────────────────────────────────

fn render_taint_graph(state: &SymbPanelState) -> impl IntoElement {
    if state.flows.is_empty() {
        return empty_state("No taint propagation data", "Run taint analysis to populate")
            .into_any_element();
    }
    div()
        .flex()
        .flex_col()
        .gap(px(6.0))
        .p(px(8.0))
        .children(state.flows.iter().map(render_taint_flow_chain))
        .into_any_element()
}

fn render_taint_flow_chain(flow: &TaintFlow) -> impl IntoElement {
    let sev_color = flow.effective_severity().color();
    div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .p(px(6.0))
        .rounded_sm()
        .border_l_2()
        .border_color(sev_color)
        .bg(colors::bg_panel())
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(6.0))
                .child(icon_colored("flag", flow.source.kind.color()))
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(colors::text_bright())
                        .truncate()
                        .child(format!(
                            "{} @ {:#x}",
                            flow.source.kind.label(),
                            flow.source.addr
                        )),
                )
                .child(div().flex_1())
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(colors::text_muted())
                        .truncate()
                        .child(format!("{} hops", flow.path_length)),
                ),
        )
        .children(flow.path.iter().enumerate().map(|(i, n)| {
            render_taint_chain_node(i, n)
        }))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(6.0))
                .child(icon_colored("target", sev_color))
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(sev_color)
                        .font_weight(FontWeight::BOLD)
                        .truncate()
                        .child(format!(
                            "{} @ {:#x}",
                            flow.sink.kind.label(),
                            flow.sink.addr
                        )),
                ),
        )
}

fn render_taint_chain_node(i: usize, n: &TaintNode) -> impl IntoElement {
    let c = if n.is_sanitized {
        colors::ok()
    } else {
        colors::text_secondary()
    };
    div()
        .flex()
        .flex_row()
        .gap(px(6.0))
        .pl(px(16.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .w(px(20.0))
                .child(format!("{}", i + 1)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::syn_address())
                .w(px(80.0))
                .child(format!("{:#010x}", n.addr)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(c)
                .flex_1()
                .child(n.instruction.clone()),
        )
}

// ── Findings view ──────────────────────────────────────────────────────────

fn render_findings_view(state: &SymbPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let flows = state.filtered_flows();
    div()
        .flex()
        .flex_col()
        .flex_1()
        .child(findings_filter_bar(state, bus))
        .child(if flows.is_empty() {
            empty_state("No findings", "Configure sources/sinks and run analysis")
                .into_any_element()
        } else {
            div()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .children(flows.iter().map(|f| {
                    render_finding_row(f, state.selected_flow == Some(f.id), bus)
                }))
                .into_any_element()
        })
}

fn findings_filter_bar(state: &SymbPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .px(px(6.0))
        .py(px(3.0))
        .child(filter_chip("All", state.findings_filter == FindingFilter::All, 0, bus))
        .child(filter_chip(
            "Critical",
            state.findings_filter == FindingFilter::MinSeverity(TaintSeverity::Critical),
            1,
            bus,
        ))
        .child(filter_chip(
            "High+",
            state.findings_filter == FindingFilter::MinSeverity(TaintSeverity::High),
            2,
            bus,
        ))
        .child(filter_chip(
            "CmdInj",
            state.findings_filter == FindingFilter::Kind(TaintSinkKind::CommandInjection),
            3,
            bus,
        ))
        .child(filter_chip(
            "BufOvf",
            state.findings_filter == FindingFilter::Kind(TaintSinkKind::BufferOverflow),
            4,
            bus,
        ))
        .child(filter_chip(
            "FmtStr",
            state.findings_filter == FindingFilter::Kind(TaintSinkKind::FormatString),
            5,
            bus,
        ))
}

fn filter_chip(label: &str, active: bool, slot: u8, bus: &Arc<EventBus>) -> impl IntoElement {
    let (bg, fg) = if active {
        (colors::bg_selection(), colors::accent())
    } else {
        (colors::bg_panel(), colors::text_secondary())
    };
    let bus = Arc::clone(bus);
    div()
        .id(("symb-filter-chip", slot as u32))
        .px(px(6.0))
        .py(px(2.0))
        .rounded_sm()
        .bg(bg)
        .text_size(px(10.0))
        .text_color(fg)
        .on_click(move |_, _, _| bus.send_command(UICommand::SymbSetFindingsFilter(slot)))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label.to_string())
}

fn render_finding_row(flow: &TaintFlow, selected: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let sev = flow.effective_severity();
    let flow_id = flow.id;
    let bus = Arc::clone(bus);
    div()
        .id(("symb-finding-row", flow_id as u32))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .px(px(8.0))
        .py(px(3.0))
        .rounded_sm()
        .bg(if selected {
            colors::bg_selection()
        } else {
            colors::bg_panel()
        })
        .on_click(move |_, _, _| bus.send_command(UICommand::SymbSelectFlow(flow_id)))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(3.0))
                .h(px(18.0))
                .bg(sev.color()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(sev.color())
                .font_weight(FontWeight::BOLD)
                .w(px(60.0))
                .child(sev.label().to_string()),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .w(px(110.0))
                .child(flow.sink.kind.label().to_string()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::syn_address())
                .w(px(90.0))
                .child(format!("{:#010x}", flow.sink.addr)),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_secondary())
                .flex_1()
                .child(format!(
                    "{} -> {}",
                    flow.source.description, flow.sink.description
                )),
        )
}

// ── Empty state ────────────────────────────────────────────────────────────

fn empty_state(title: &str, hint: &str) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap(px(6.0))
        .p(px(20.0))
        .child(icon_sized("alembic", 28.0, 28.0))
        .child(
            div()
                .text_size(px(12.0))
                .text_color(colors::text_secondary())
                .truncate()
                .child(title.to_string()),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(hint.to_string()),
        )
}

// ── Main render ────────────────────────────────────────────────────────────

pub fn render_symb_panel(
    state: &SymbPanelState,
    _ui: Arc<Mutex<UIState>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let body: gpui::AnyElement = match state.mode {
        SymbMode::Run => render_run_view(state, bus).into_any_element(),
        SymbMode::State => render_state_view(state).into_any_element(),
        SymbMode::Paths => render_paths_view(state, bus).into_any_element(),
        SymbMode::TaintConfig => render_taint_config(state, bus).into_any_element(),
        SymbMode::TaintGraph => render_taint_graph(state).into_any_element(),
        SymbMode::TaintFindings => render_findings_view(state, bus).into_any_element(),
    };

    div()
        .flex()
        .flex_col()
        .size_full()
        .bg(colors::bg_base())
        .child(header("Symbolic & Taint", state))
        .child(mode_bar(state, bus))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .child(body),
        )
        .child(status_strip(state))
}

// ─── ensure_used scaffolding ────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_symb_panel() {
    let modes = [
        SymbMode::Run,
        SymbMode::State,
        SymbMode::Paths,
        SymbMode::TaintConfig,
        SymbMode::TaintGraph,
        SymbMode::TaintFindings,
    ];
    for m in modes {
        assert!(!m.label().is_empty());
        assert!(!m.icon().is_empty());
        match m {
            SymbMode::Run
            | SymbMode::State
            | SymbMode::Paths
            | SymbMode::TaintConfig
            | SymbMode::TaintGraph
            | SymbMode::TaintFindings => {}
        }
    }

    let mut s = SymbPanelState::new();
    s.set_func(1, "test".into());
    s.begin_run("symb");
    s.finish_run("symb");
    s.state = SymStateSnapshot {
        step: 1,
        pc: 0x4000_0000,
        registers: vec![SymRegister {
            name: "rax".into(),
            expr: "sym_input".into(),
            concrete: Some(0x10),
        }],
        memory: vec![SymMemCell {
            addr: 0x7fff_0000,
            width: 8,
            expr: "sym_buf[0]".into(),
        }],
        path_conditions: vec![SymPathCond {
            addr: 0x4001_0000,
            expr: "rax > 0".into(),
            taken: true,
        }],
    };
    s.paths.push(SymPathNode {
        id: 1,
        parent: None,
        addr: 0x4000_0000,
        condition: "true".into(),
        feasible: true,
        completed: false,
        depth: 0,
    });
    s.selected_path = Some(1);
    s.findings_filter = FindingFilter::MinSeverity(TaintSeverity::High);
    let _ = s.filtered_flows();
    s.findings_filter = FindingFilter::Kind(TaintSinkKind::CommandInjection);
    let _ = s.filtered_flows();
    s.findings_filter = FindingFilter::All;
    let _ = s.filtered_flows();

    // Touch render functions
    let ui = Arc::new(Mutex::new(UIState::new()));
    let bus = Arc::new(EventBus::new());
    let _ = render_symb_panel(&s, ui, &bus);
    let _ = render_run_view(&s, &bus);
    let _ = render_state_view(&s);
    let _ = render_paths_view(&s, &bus);
    let _ = render_taint_config(&s, &bus);
    let _ = render_taint_graph(&s);
    let _ = render_findings_view(&s, &bus);
    let _ = action_btn("x", "play", true, UICommand::SymbStop, &bus);
    let _ = progress_bar(0.5, true);
    let _ = filter_chip("x", false, 0, &bus);
    let _ = kv("k", "v");
    let _ = section_header("X", 0);
    let _ = empty_state("a", "b");
    let _ = render_register_row(&s.state.registers[0]);
    let _ = render_mem_row(&s.state.memory[0]);
    let _ = render_pc_row(&s.state.path_conditions[0]);
    let _ = render_path_node(&s.paths[0], true, &bus);
    let _ = render_source_chip(&s.taint_config.sources[0]);
    let _ = render_sink_chip(&s.taint_config.sinks[0]);

    let src = TaintSource {
        id: 1,
        addr: 0x10,
        kind: TaintSourceKind::NetworkInput,
        register: None,
        memory_addr: None,
        description: "src".into(),
        func_name: "f".into(),
    };
    let sink = TaintSink {
        id: 2,
        addr: 0x20,
        kind: TaintSinkKind::BufferOverflow,
        description: "snk".into(),
        func_name: "f".into(),
        severity: TaintSeverity::High,
    };
    let node = TaintNode {
        addr: 0x18,
        instruction: "mov rax, [rdi]".into(),
        register: None,
        memory_addr: None,
        is_sanitized: false,
        is_conditional: false,
    };
    let flow = TaintFlow::new(src, sink, vec![node.clone()]);
    let _ = render_taint_flow_chain(&flow);
    let _ = render_taint_chain_node(0, &node);
    let _ = render_finding_row(&flow, true, &bus);

    s.selected_flow = Some(flow.id);
    s.flows.push(flow);
    let _ = render_taint_graph(&s);
    let _ = render_findings_view(&s, &bus);
    let _ = findings_filter_bar(&s, &bus);
    let _ = mode_bar(&s, &bus);
    let _ = mode_tab(SymbMode::Run, true, &bus);
    let _ = status_strip(&s);
    let _ = header("t", &s);

    // refresh
    let data = crate::core::app_state::AppData::new();
    s.refresh(&data, 1, Some(1));
}
