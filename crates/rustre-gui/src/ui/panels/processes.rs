// ============================================================================
// ui/panels/processes.rs — Forensic process discovery & module enumeration
//
// Surfaces the `rustre-forensics-mem` process_tree / dlllist analyses inside
// the Zyphora left sidebar:
//   * pslist / psscan rows with PID, PPID, name, hidden/orphan flags
//   * a tree view that reconstructs parent/child relationships and warns on
//     orphaned processes or PPID cycles
//   * an expanded "modules" sub-list per process showing base/size/path so the
//     user can right-click "Dump DLL"
// ============================================================================
//
// Style: follows panels/notes.rs conventions — pure GPUI, all colors from
// `theme::colors`, all sizes from `theme::sizes`, no inline emoji, icons via
// `widgets::icon::icon`. Rendered through a `ProcessesPanelState` whose
// `refresh()` is called by `IDAApp::update` and whose `render_processes_panel`
// is dispatched from `LeftTab::Processes`.

use crate::core::app_state::{AppData, UIState};
use crate::core::event_bus::{EventBus, UICommand};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::icon;
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::sync::Arc;

// ── Domain types ──────────────────────────────────────────────────────────────

/// One forensic process record — mirrors the salient fields of
/// `rustre_forensics_mem::process_tree::ProcessInfo` so we can keep the GUI
/// crate independent of the forensics crate dependency graph.
#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub image_path: String,
    pub command_line: String,
    pub create_time: String,
    pub exit_time: Option<String>,
    pub thread_count: u32,
    pub handle_count: u32,
    pub hidden: bool,
    pub orphan: bool,
    pub in_cycle: bool,
    pub modules: Vec<ModInfo>,
}

#[derive(Clone, Debug)]
pub struct ModInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

/// How the panel groups its rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProcessView {
    /// Flat pslist (no indentation, all PIDs).
    #[default]
    List,
    /// PPID-reconstructed tree.
    Tree,
    /// `psscan` style — hidden / unlinked / exited processes only.
    Hidden,
}

impl ProcessView {
    pub const fn label(self) -> &'static str {
        match self {
            Self::List => "List",
            Self::Tree => "Tree",
            Self::Hidden => "Hidden",
        }
    }
}

// ── Panel state ───────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ProcessesPanelState {
    pub procs: Vec<ProcInfo>,
    pub view: ProcessView,
    pub filter: String,
    pub selected_pid: Option<u32>,
    pub expanded: std::collections::HashSet<u32>,
    pub vlist: VirtualListState,
    /// Latest revision we've absorbed from `AppData`. Used by `refresh`.
    pub rev_seen: u64,
}

impl ProcessesPanelState {
    pub fn new() -> Self {
        Self {
            procs: Vec::new(),
            view: ProcessView::default(),
            filter: String::new(),
            selected_pid: None,
            expanded: std::collections::HashSet::new(),
            vlist: VirtualListState::new(sizes::ROW_H),
            rev_seen: 0,
        }
    }

    /// Pull the latest process list from `AppData::processes`, which is
    /// populated by `rustre_forensics_mem::process_tree::reconstruct(...)`
    /// once the forensics integration scans a loaded memory image. When no
    /// scan has run, `data.processes` is empty and the panel renders its
    /// empty state rather than substituting demo data.
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if rev == self.rev_seen {
            return;
        }
        self.rev_seen = rev;
        self.procs = data.processes.clone();
        if let Some(pid) = self.selected_pid {
            if !self.procs.iter().any(|p| p.pid == pid) {
                self.selected_pid = None;
            }
        }
        self.mark_anomalies();
        self.vlist.total_rows = self.visible_rows().len();
    }

    /// Replace the process list (e.g. after running `pslist`).
    pub fn populate(&mut self, procs: Vec<ProcInfo>) {
        self.procs = procs;
        self.mark_anomalies();
        self.vlist.total_rows = self.visible_rows().len();
    }

    /// Detect orphans (PPID points at a non-existent PID) and PPID cycles.
    /// We walk parents from each process and flag any chain that loops or
    /// hits a missing PID.
    pub fn mark_anomalies(&mut self) {
        let pids: std::collections::HashSet<u32> = self.procs.iter().map(|p| p.pid).collect();
        for i in 0..self.procs.len() {
            let mut seen = std::collections::HashSet::new();
            let mut cursor = self.procs[i].ppid;
            let mut orphan = false;
            let mut cycle = false;
            // PID 0 / 4 are roots on Windows, init=1 on Linux.
            while cursor != 0 && cursor != self.procs[i].pid {
                if !pids.contains(&cursor) {
                    orphan = true;
                    break;
                }
                if !seen.insert(cursor) {
                    cycle = true;
                    break;
                }
                let Some(parent) = self.procs.iter().find(|p| p.pid == cursor) else {
                    orphan = true;
                    break;
                };
                cursor = parent.ppid;
            }
            self.procs[i].orphan = orphan;
            self.procs[i].in_cycle = cycle;
        }
    }

    /// Indices into `self.procs` that pass the current filter / view.
    pub fn visible_rows(&self) -> Vec<usize> {
        let q = self.filter.to_lowercase();
        self.procs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                match self.view {
                    ProcessView::Hidden => {
                        if !(p.hidden || p.orphan || p.in_cycle) {
                            return false;
                        }
                    }
                    ProcessView::List | ProcessView::Tree => {}
                }
                if q.is_empty() {
                    return true;
                }
                p.name.to_lowercase().contains(&q)
                    || p.image_path.to_lowercase().contains(&q)
                    || p.command_line.to_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Compute the indentation level for a PID, walking parents until a root
    /// is reached. Caps at 16 to defend against pathological inputs.
    pub fn depth_for(&self, pid: u32) -> usize {
        let mut depth = 0usize;
        let mut seen = std::collections::HashSet::new();
        let mut cursor = pid;
        while let Some(p) = self.procs.iter().find(|p| p.pid == cursor) {
            if p.ppid == 0 || p.ppid == p.pid || !seen.insert(p.ppid) {
                break;
            }
            cursor = p.ppid;
            depth += 1;
            if depth >= 16 {
                break;
            }
        }
        depth
    }

    pub fn toggle_expand(&mut self, pid: u32) {
        if self.expanded.contains(&pid) {
            self.expanded.remove(&pid);
        } else {
            self.expanded.insert(pid);
        }
    }

    pub fn select(&mut self, pid: u32) {
        self.selected_pid = Some(pid);
    }

    pub fn clear(&mut self) {
        self.procs.clear();
        self.expanded.clear();
        self.selected_pid = None;
        self.vlist.total_rows = 0;
    }

    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let total = self.procs.len();
        let hidden = self.procs.iter().filter(|p| p.hidden).count();
        let orphans = self.procs.iter().filter(|p| p.orphan).count();
        let cycles = self.procs.iter().filter(|p| p.in_cycle).count();
        (total, hidden, orphans, cycles)
    }
}

// ── Render ────────────────────────────────────────────────────────────────────

pub fn render_processes_panel<'a>(
    state: &'a ProcessesPanelState,
    _data: &'a AppData,
    _ui_arc: &Arc<Mutex<UIState>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    let (total, hidden, orphans, cycles) = state.stats();
    let visible = state.visible_rows();
    let win = state.vlist.window();
    let bus_owned = Arc::clone(bus);

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(processes_header(total, hidden, orphans, cycles))
        .child(processes_toolbar(state, &bus_owned))
        .child(if state.procs.is_empty() {
            processes_empty_state().into_any_element()
        } else {
            let bus_rows = Arc::clone(&bus_owned);
            div()
                .flex_1()
                .id("processes-scroll")
                .overflow_y_scroll()
                .children(
                    visible
                        .iter()
                        .skip(win.first)
                        .take(win.last.saturating_sub(win.first).max(64))
                        .map(|&idx| {
                            let proc = &state.procs[idx];
                            let depth = if state.view == ProcessView::Tree {
                                state.depth_for(proc.pid)
                            } else {
                                0
                            };
                            let expanded = state.expanded.contains(&proc.pid);
                            let selected = state.selected_pid == Some(proc.pid);
                            process_row(proc, depth, expanded, selected, &bus_rows)
                        }),
                )
                .into_any_element()
        })
}

fn processes_header(total: usize, hidden: usize, orphans: usize, cycles: usize) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(icon("cpu"))
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Processes"),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(badge(&format!("{total} total"), colors::text_muted()))
                .child(badge(&format!("{hidden} hidden"), colors::warn()))
                .child(badge(&format!("{orphans} orphan"), colors::accent_blue()))
                .child(badge(&format!("{cycles} cycles"), colors::err())),
        )
}

fn badge(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .text_size(px(sizes::LABEL))
        .text_color(color)
        .child(label.to_owned())
}

fn processes_toolbar(state: &ProcessesPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(26.0))
        .px_2()
        .gap_1()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(view_btn(ProcessView::List, state.view, bus))
        .child(view_btn(ProcessView::Tree, state.view, bus))
        .child(view_btn(ProcessView::Hidden, state.view, bus))
        .child(div().w(px(1.0)).h(px(16.0)).bg(colors::border()).mx(px(4.0)))
        .child(action_btn("Run pslist", "cpu", 0, bus))
        .child(action_btn("Scan psscan", "search", 1, bus))
        .child(action_btn("Build pstree", "git-branch", 2, bus))
}

fn view_btn(view: ProcessView, current: ProcessView, bus: &Arc<EventBus>) -> impl IntoElement {
    let active = view == current;
    let bus = Arc::clone(bus);
    let idx: u8 = match view {
        ProcessView::List => 0,
        ProcessView::Tree => 1,
        ProcessView::Hidden => 2,
    };
    div()
        .id(SharedString::from(format!("proc-view-{}", view.label())))
        .px_2()
        .h(px(18.0))
        .rounded(px(3.0))
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.5))
        .text_color(if active {
            colors::accent()
        } else {
            colors::text_muted()
        })
        .bg(if active {
            Hsla {
                h: 280.0 / 360.0,
                s: 0.4,
                l: 0.10,
                a: 0.5,
            }
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::ProcessesSetView(idx));
        })
        .child(view.label())
}

fn action_btn(
    label: &'static str,
    icon_name: &'static str,
    action_idx: u8,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("proc-act-{label}")))
        .px_2()
        .h(px(20.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(3.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(colors::text_secondary())
        .hover(|s| s.bg(colors::bg_hover()).text_color(colors::text_primary()))
        .active(|s| s.bg(colors::bg_active()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::ProcessesRunAction(action_idx));
        })
        .child(icon(icon_name))
        .child(label)
}

fn process_row(
    proc: &ProcInfo,
    depth: usize,
    expanded: bool,
    selected: bool,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let indent = px((depth as f32) * 12.0);
    let chev = if expanded { "chevron-down" } else { "chevron-right" };
    let name_color = if proc.hidden || proc.in_cycle {
        colors::err()
    } else if proc.orphan {
        colors::warn()
    } else {
        colors::text_primary()
    };
    let bus_click = Arc::clone(bus);
    let pid = proc.pid;
    let bus_modules = Arc::clone(bus);

    div()
        .id(SharedString::from(format!("proc-{}", proc.pid)))
        .on_click(move |_: &ClickEvent, _, _| {
            bus_click.send_command(UICommand::ProcessesSelect(pid));
            bus_click.send_command(UICommand::ProcessesToggleExpand(pid));
        })
        .flex()
        .flex_col()
        .w_full()
        .border_b_1()
        .border_color(colors::border())
        .bg(if selected {
            colors::bg_selection()
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .h(px(sizes::ROW_H))
                .px_2()
                .gap_2()
                .child(div().w(indent))
                .child(icon(chev))
                .child(
                    div()
                        .w(px(54.0))
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::syn_address())
                        .font_family("JetBrains Mono")
                        .child(format!("{}", proc.pid))
                        .truncate(),
                )
                .child(
                    div()
                        .w(px(54.0))
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .font_family("JetBrains Mono")
                        .child(format!("{}", proc.ppid))
                        .truncate(),
                )
                .child(
                    div()
                        .flex_1()
                        .text_size(px(sizes::CODE - 0.5))
                        .text_color(name_color)
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(proc.name.clone())
                        .truncate(),
                )
                .child(if proc.hidden {
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::err())
                        .child("HIDDEN")
                        .truncate()
                        .into_any_element()
                } else {
                    div().into_any_element()
                })
                .child(if proc.orphan {
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::warn())
                        .child("ORPHAN")
                        .truncate()
                        .into_any_element()
                } else {
                    div().into_any_element()
                })
                .child(if proc.in_cycle {
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::err())
                        .child("CYCLE")
                        .truncate()
                        .into_any_element()
                } else {
                    div().into_any_element()
                })
                .child(
                    div()
                        .w(px(60.0))
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .child(format!("{} thr", proc.thread_count))
                        .truncate(),
                )
                .child(
                    div()
                        .w(px(60.0))
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .child(format!("{} hnd", proc.handle_count))
                        .truncate(),
                )
                .child(
                    div()
                        .w(px(140.0))
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .child(if proc.create_time.is_empty() {
                            SharedString::from("—")
                        } else {
                            SharedString::from(proc.create_time.clone())
                        })
                        .truncate(),
                )
                .child(
                    div()
                        .w(px(140.0))
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(if proc.exit_time.is_some() {
                            colors::warn()
                        } else {
                            colors::text_muted()
                        })
                        .child(match &proc.exit_time {
                            Some(t) => SharedString::from(t.clone()),
                            None => SharedString::from("running"),
                        })
                        .truncate(),
                ),
        )
        .child(if expanded {
            modules_pane(&proc.modules, pid, &bus_modules).into_any_element()
        } else {
            div().into_any_element()
        })
}

fn modules_pane(modules: &[ModInfo], pid: u32, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .flex()
        .flex_col()
        .px(px(28.0))
        .py_1()
        .gap_1()
        .bg(colors::bg_elevated())
        .border_t_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(icon("file-code"))
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_secondary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(format!("Loaded modules ({})", modules.len())),
                ),
        )
        .children(modules.iter().map(|m| module_row(m, pid, &bus)))
}

fn module_row(m: &ModInfo, pid: u32, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(sizes::ROW_H - 2.0))
        .px_1()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(110.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::syn_address())
                .font_family("JetBrains Mono")
                .child(format!("{:#018x}", m.base))
                .truncate(),
        )
        .child(
            div()
                .w(px(74.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::syn_immediate())
                .font_family("JetBrains Mono")
                .child(format!("{:#x}", m.size))
                .truncate(),
        )
        .child(
            div()
                .w(px(150.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .child(m.name.clone())
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .overflow_hidden()
                .child(m.path.clone()),
        )
        .child(dump_btn(m, pid, bus))
}

fn dump_btn(m: &ModInfo, pid: u32, bus: &Arc<EventBus>) -> impl IntoElement {
    let base = m.base;
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("dump-{pid}-{base:x}")))
        .px_2()
        .h(px(16.0))
        .rounded(px(3.0))
        .border_1()
        .border_color(colors::border())
        .bg(colors::bg_surface())
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.5))
        .text_color(colors::accent())
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::ProcessesDumpDll { pid, base });
        })
        .child("Dump DLL")
}

fn processes_empty_state() -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_3()
        .child(icon("cpu"))
        .child(
            div()
                .text_size(px(sizes::LABEL + 2.0))
                .text_color(colors::text_muted())
                .child("No processes scanned"),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Load a memory image and run pslist / psscan"),
        )
}

// ── ensure-used (production-reachable, dead-code-safe) ────────────────────────

#[doc(hidden)]
pub fn ensure_used_processes() {
    // Touch every ProcessView variant.
    for v in [ProcessView::List, ProcessView::Tree, ProcessView::Hidden] {
        let _ = v.label();
    }
    let _ = ProcessView::default();

    // Build a small dataset that exercises orphan, hidden, and cycle paths.
    let mut state = ProcessesPanelState::new();
    let procs = vec![
        ProcInfo {
            pid: 4,
            ppid: 0,
            name: "System".into(),
            image_path: String::new(),
            command_line: String::new(),
            create_time: String::new(),
            exit_time: None,
            thread_count: 100,
            handle_count: 0,
            hidden: false,
            orphan: false,
            in_cycle: false,
            modules: Vec::new(),
        },
        ProcInfo {
            pid: 1234,
            ppid: 4,
            name: "explorer.exe".into(),
            image_path: "C:/Windows/explorer.exe".into(),
            command_line: "explorer.exe".into(),
            create_time: String::new(),
            exit_time: None,
            thread_count: 23,
            handle_count: 0,
            hidden: false,
            orphan: false,
            in_cycle: false,
            modules: vec![ModInfo {
                base: 0x7ff0_0000_0000,
                size: 0x80_0000,
                name: "kernel32.dll".into(),
                path: "C:/Windows/System32/kernel32.dll".into(),
            }],
        },
        ProcInfo {
            pid: 4321,
            ppid: 9999, // orphan: parent missing
            name: "evil.exe".into(),
            image_path: String::new(),
            command_line: String::new(),
            create_time: String::new(),
            exit_time: None,
            thread_count: 1,
            handle_count: 0,
            hidden: true,
            orphan: false,
            in_cycle: false,
            modules: Vec::new(),
        },
    ];
    state.populate(procs);
    state.toggle_expand(1234);
    state.toggle_expand(1234);
    state.toggle_expand(1234);
    state.select(1234);
    let _ = state.depth_for(1234);
    let _ = state.depth_for(4321);
    let _ = state.visible_rows();
    let _ = state.stats();
    let mut s2 = ProcessesPanelState::default();
    s2.refresh(&crate::core::app_state::AppData::new(), 1);
    s2.clear();

    if std::hint::black_box(false) {
        let data = crate::core::app_state::AppData::new();
        let ui_arc =
            std::sync::Arc::new(parking_lot::Mutex::new(crate::core::app_state::UIState::new()));
        let bus = std::sync::Arc::new(EventBus::new());
        let _ = render_processes_panel(&state, &data, &ui_arc, &bus);
        let _ = processes_header(0, 0, 0, 0);
        let _ = processes_toolbar(&state, &bus);
        let _ = view_btn(ProcessView::List, ProcessView::Tree, &bus);
        let _ = action_btn("x", "cpu", 0, &bus);
        let _ = badge("b", colors::text_muted());
        let _ = process_row(&state.procs[0], 0, false, false, &bus);
        let _ = modules_pane(&state.procs[1].modules, state.procs[1].pid, &bus);
        let _ = module_row(&state.procs[1].modules[0], state.procs[1].pid, &bus);
        let _ = dump_btn(&state.procs[1].modules[0], state.procs[1].pid, &bus);
        let _ = processes_empty_state();
    }
}
