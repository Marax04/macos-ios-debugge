// ============================================================================
// ui/panels/variables.rs  —  Local variables & stack frame panel
// ============================================================================

use crate::core::app_state::UIState;
use gpui::{div, hsla, px, Hsla, IntoElement, ParentElement, Styled};
use parking_lot::Mutex;
use std::sync::Arc;

// ─── Variable scope ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarScope {
    Local,
    Parameter,
    Global,
    Register,
    Temporary,
}

impl VarScope {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Parameter => "param",
            Self::Global => "global",
            Self::Register => "reg",
            Self::Temporary => "tmp",
        }
    }

    pub fn color(self) -> Hsla {
        match self {
            Self::Local => hsla(0.6, 0.6, 0.65, 1.0),
            Self::Parameter => hsla(0.38, 0.6, 0.65, 1.0),
            Self::Global => hsla(0.15, 0.6, 0.65, 1.0),
            Self::Register => hsla(0.05, 0.7, 0.65, 1.0),
            Self::Temporary => hsla(0.0, 0.0, 0.45, 1.0),
        }
    }
}

// ─── Variable location (where it lives) ──────────────────────────────────────

#[derive(Clone, Debug)]
pub enum VarLocation {
    StackOffset(i64),     // rbp-0x10 style
    Register(String),     // "rax", "xmm0", etc.
    GlobalAddr(u64),      // .data / .bss address
    Composite(Vec<Self>), // split across multiple regs/mem
}

impl VarLocation {
    pub fn display(&self) -> String {
        match self {
            Self::StackOffset(off) => {
                if *off < 0 {
                    // `{:#x}` on a negative integer prints the two's-complement
                    // bit pattern, so `-16i64` came out as `0xfffffffffffffff0`
                    // and every local variable rendered as `[rbp0xffff…f0]`.
                    // The sign has to be written separately and the magnitude
                    // formatted from the absolute value.
                    format!("[rbp-{:#x}]", off.unsigned_abs())
                } else {
                    format!("[rbp+{off:#x}]")
                }
            }
            Self::Register(r) => r.clone(),
            Self::GlobalAddr(a) => format!("{a:#010x}"),
            Self::Composite(parts) => parts
                .iter()
                .map(Self::display)
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

// ─── Variable value (current) ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum VarValue {
    Unknown,
    Unavailable, // debugger connected but not readable
    U64(u64),
    I64(i64),
    F64(f64),
    Bytes(Vec<u8>), // raw bytes when type unknown
    Pointer { addr: u64, deref: Option<Box<Self>> },
    Struct(Vec<(String, Self)>),
    Array(Vec<Self>),
    String(String),
}

impl VarValue {
    pub fn display(&self) -> String {
        match self {
            Self::Unknown => "<unknown>".to_string(),
            Self::Unavailable => "<unavail>".to_string(),
            Self::U64(v) => format!("{v:#x} ({v})"),
            Self::I64(v) => format!("{v}"),
            Self::F64(v) => format!("{v:.6}"),
            Self::Bytes(b) => {
                let s: Vec<String> = b.iter().map(|x| format!("{x:02X}")).collect();
                format!("[{}]", s.join(" "))
            }
            Self::Pointer { addr, deref } => {
                let inner = deref
                    .as_ref()
                    .map_or_else(String::new, |v| format!(" -> {}", v.display()));
                format!("{addr:#010x}{inner}")
            }
            Self::Struct(fields) => {
                let s: Vec<String> = fields
                    .iter()
                    .map(|(n, v)| format!("{}: {}", n, v.display()))
                    .collect();
                format!("{{ {} }}", s.join(", "))
            }
            Self::Array(items) => {
                let n = items.len();
                format!("[{n} items]")
            }
            Self::String(s) => format!("\"{s}\""),
        }
    }

    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown | Self::Unavailable)
    }

    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            Self::Pointer { addr, .. } => Some(*addr),
            _ => None,
        }
    }
}

// ─── A single variable entry ──────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Variable {
    pub id: u64,
    pub name: String,
    pub type_name: String,
    pub scope: VarScope,
    pub location: VarLocation,
    pub value: VarValue,
    pub size_bytes: usize,
    pub is_pinned: bool,
    pub is_modified: bool, // changed since last stop
    pub notes: String,
    pub live_range: Option<(u64, u64)>, // (start_addr, end_addr)
}

impl Variable {
    pub fn new(
        id: u64,
        name: &str,
        type_name: &str,
        scope: VarScope,
        location: VarLocation,
    ) -> Self {
        Self {
            id,
            name: name.to_string(),
            type_name: type_name.to_string(),
            scope,
            location,
            value: VarValue::Unknown,
            size_bytes: 0,
            is_pinned: false,
            is_modified: false,
            notes: String::new(),
            live_range: None,
        }
    }
}

// ─── Stack frame ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct StackFrame {
    pub frame_index: usize,
    pub func_addr: u64,
    pub func_name: String,
    pub ret_addr: u64,
    pub frame_base: u64,
    pub variables: Vec<Variable>,
    pub is_current: bool,
}

impl StackFrame {
    pub fn param_vars(&self) -> impl Iterator<Item = &Variable> {
        self.variables
            .iter()
            .filter(|v| v.scope == VarScope::Parameter)
    }

    pub fn local_vars(&self) -> impl Iterator<Item = &Variable> {
        self.variables.iter().filter(|v| v.scope == VarScope::Local)
    }

    pub fn reg_vars(&self) -> impl Iterator<Item = &Variable> {
        self.variables
            .iter()
            .filter(|v| v.scope == VarScope::Register)
    }
}

// ─── Panel sort & filter ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VarSort {
    Name,
    Type,
    #[default]
    Offset,
    Scope,
}

impl VarSort {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Type => "Type",
            Self::Offset => "Offset",
            Self::Scope => "Scope",
        }
    }
}

// ─── Panel state ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShowFlag {
    Params,
    Locals,
    Registers,
    ModifiedOnly,
    FrameList,
}

#[derive(Clone, Debug)]
pub struct ShowFlags {
    enabled: std::collections::HashSet<ShowFlag>,
}

impl ShowFlags {
    pub fn get(&self, f: ShowFlag) -> bool {
        self.enabled.contains(&f)
    }
    pub fn set(&mut self, f: ShowFlag, on: bool) {
        if on {
            self.enabled.insert(f);
        } else {
            self.enabled.remove(&f);
        }
    }
}

// Convenience field-style accessors used by call sites.
impl ShowFlags {
    pub fn params(&self) -> bool {
        self.get(ShowFlag::Params)
    }
    pub fn locals(&self) -> bool {
        self.get(ShowFlag::Locals)
    }
    pub fn registers(&self) -> bool {
        self.get(ShowFlag::Registers)
    }
    pub fn modified_only(&self) -> bool {
        self.get(ShowFlag::ModifiedOnly)
    }
    pub fn frame_list(&self) -> bool {
        self.get(ShowFlag::FrameList)
    }
}

impl Default for ShowFlags {
    fn default() -> Self {
        let mut enabled = std::collections::HashSet::new();
        enabled.insert(ShowFlag::Params);
        enabled.insert(ShowFlag::Locals);
        enabled.insert(ShowFlag::Registers);
        enabled.insert(ShowFlag::FrameList);
        Self { enabled }
    }
}

#[derive(Clone, Debug, Default)]
pub struct VariablesPanelState {
    pub frames: Vec<StackFrame>,
    pub selected_frame: usize,
    pub selected_var: Option<u64>,
    pub sort: VarSort,
    pub filter: String,
    pub show: ShowFlags,
    pub expanded_structs: std::collections::HashSet<u64>, // var ids with expanded struct view
    pub pinned_vars: Vec<Variable>,                       // vars pinned for persistent tracking
}

impl VariablesPanelState {
    pub fn current_frame(&self) -> Option<&StackFrame> {
        self.frames.get(self.selected_frame)
    }

    pub fn visible_vars(&self) -> Vec<&Variable> {
        let Some(frame) = self.current_frame() else {
            return vec![];
        };

        let filter_lower = self.filter.to_lowercase();
        let mut vars: Vec<&Variable> = frame
            .variables
            .iter()
            .filter(|v| {
                // scope filters
                let scope_ok = match v.scope {
                    VarScope::Parameter => self.show.params(),
                    VarScope::Local => self.show.locals(),
                    VarScope::Register => self.show.registers(),
                    _ => true,
                };
                if !scope_ok {
                    return false;
                }

                // modified filter
                if self.show.modified_only() && !v.is_modified {
                    return false;
                }

                // text filter
                if !filter_lower.is_empty() {
                    let matches = v.name.to_lowercase().contains(&filter_lower)
                        || v.type_name.to_lowercase().contains(&filter_lower);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .collect();

        vars.sort_by(|a, b| match self.sort {
            VarSort::Name => a.name.cmp(&b.name),
            VarSort::Type => a.type_name.cmp(&b.type_name),
            VarSort::Offset => {
                let ao = if let VarLocation::StackOffset(o) = &a.location {
                    *o
                } else {
                    0
                };
                let bo = if let VarLocation::StackOffset(o) = &b.location {
                    *o
                } else {
                    0
                };
                ao.cmp(&bo)
            }
            VarSort::Scope => (a.scope as u8).cmp(&(b.scope as u8)),
        });
        vars
    }

    pub fn total_stack_size(&self) -> i64 {
        let Some(frame) = self.current_frame() else {
            return 0;
        };
        let min_off = frame
            .variables
            .iter()
            .filter_map(|v| {
                if let VarLocation::StackOffset(o) = &v.location {
                    Some(*o)
                } else {
                    None
                }
            })
            .min()
            .unwrap_or(0);
        min_off.abs()
    }
}

// ─── Render helpers ───────────────────────────────────────────────────────────

fn scope_badge(scope: VarScope) -> impl IntoElement {
    div()
        .px(px(5.0))
        .py(px(1.0))
        .rounded(px(3.0))
        .text_size(px(9.0))
        .bg(hsla(0.0, 0.0, 0.15, 1.0))
        .text_color(scope.color())
        .truncate()
        .child(scope.label().to_string())
}

fn sort_btn(label: &str, active: bool) -> impl IntoElement {
    div()
        .px(px(7.0))
        .py(px(1.0))
        .rounded(px(3.0))
        .text_size(px(10.0))
        .bg(if active {
            hsla(0.6, 0.4, 0.25, 1.0)
        } else {
            hsla(0.0, 0.0, 0.15, 1.0)
        })
        .text_color(if active {
            hsla(0.6, 0.8, 0.85, 1.0)
        } else {
            hsla(0.0, 0.0, 0.5, 1.0)
        })
        .truncate()
        .child(label.to_string())
}

fn filter_toggle(label: &str, active: bool) -> impl IntoElement {
    div()
        .px(px(6.0))
        .py(px(1.0))
        .rounded(px(3.0))
        .text_size(px(10.0))
        .bg(hsla(0.0, 0.0, 0.13, 1.0))
        .text_color(if active {
            hsla(0.38, 0.7, 0.65, 1.0)
        } else {
            hsla(0.0, 0.0, 0.35, 1.0)
        })
        .truncate()
        .child(label.to_string())
}

fn render_value_cell(value: &VarValue, is_modified: bool) -> impl IntoElement {
    let text = value.display();
    let color = if is_modified {
        hsla(0.05, 0.9, 0.65, 1.0)
    } else if value.is_known() {
        hsla(0.6, 0.5, 0.75, 1.0)
    } else {
        hsla(0.0, 0.0, 0.35, 1.0)
    };
    div()
        .flex_1()
        .text_size(px(11.0))
        .text_color(color)
        .overflow_hidden()
        .truncate()
        .child(text)
}

fn render_var_row(var: &Variable, selected: bool) -> impl IntoElement {
    let is_selected = selected;
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .px(px(8.0))
        .py(px(2.0))
        .bg(if is_selected {
            hsla(0.6, 0.3, 0.2, 0.4)
        } else if var.is_modified {
            hsla(0.05, 0.3, 0.1, 0.3)
        } else {
            hsla(0.0, 0.0, 0.0, 0.0)
        })
        // Modified indicator
        .child(
            div()
                .w(px(4.0))
                .h(px(4.0))
                .rounded_full()
                .bg(if var.is_modified {
                    hsla(0.05, 0.9, 0.6, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.0, 0.0)
                }),
        )
        // Pin indicator
        .child(
            div()
                .text_size(px(9.0))
                .text_color(hsla(0.15, 0.7, 0.6, 1.0))
                .child(if var.is_pinned { "*" } else { "" }),
        )
        // Scope badge
        .child(scope_badge(var.scope))
        // Name
        .child(
            div()
                .w(px(120.0))
                .text_size(px(12.0))
                .text_color(hsla(0.0, 0.0, 0.85, 1.0))
                .overflow_hidden()
                .truncate()
                .child(var.name.clone()),
        )
        // Type
        .child(
            div()
                .w(px(100.0))
                .text_size(px(11.0))
                .text_color(hsla(0.38, 0.4, 0.6, 1.0))
                .overflow_hidden()
                .truncate()
                .child(var.type_name.clone()),
        )
        // Location
        .child(
            div()
                .w(px(80.0))
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.4, 1.0))
                .overflow_hidden()
                .truncate()
                .child(var.location.display()),
        )
        // Value
        .child(render_value_cell(&var.value, var.is_modified))
}

fn render_frame_list(state: &VariablesPanelState) -> impl IntoElement {
    let mut list = div()
        .flex()
        .flex_col()
        .w(px(220.0))
        .bg(hsla(0.0, 0.0, 0.09, 1.0))
        .border_r_1()
        .border_color(hsla(0.0, 0.0, 0.18, 1.0));

    list = list.child(
        div()
            .px(px(8.0))
            .py(px(4.0))
            .border_b_1()
            .border_color(hsla(0.0, 0.0, 0.18, 1.0))
            .text_size(px(10.0))
            .text_color(hsla(0.0, 0.0, 0.4, 1.0))
            .truncate()
            .child("CALL STACK"),
    );

    for (i, frame) in state.frames.iter().enumerate() {
        let is_selected = i == state.selected_frame;
        list = list.child(
            div()
                .flex()
                .flex_col()
                .px(px(8.0))
                .py(px(4.0))
                .bg(if is_selected {
                    hsla(0.6, 0.3, 0.2, 0.4)
                } else {
                    hsla(0.0, 0.0, 0.0, 0.0)
                })
                .border_b_1()
                .border_color(hsla(0.0, 0.0, 0.13, 1.0))
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap(px(6.0))
                        .child(
                            div()
                                .w(px(14.0))
                                .text_size(px(10.0))
                                .text_color(hsla(0.0, 0.0, 0.35, 1.0))
                                .truncate()
                                .child(format!("#{i}")),
                        )
                        .child(if frame.is_current {
                            div()
                                .w(px(6.0))
                                .h(px(6.0))
                                .rounded_full()
                                .bg(hsla(0.38, 0.7, 0.6, 1.0))
                        } else {
                            div().w(px(6.0)).h(px(6.0))
                        })
                        .child(
                            div()
                                .flex_1()
                                .text_size(px(11.0))
                                .text_color(if is_selected {
                                    hsla(0.0, 0.0, 0.9, 1.0)
                                } else {
                                    hsla(0.0, 0.0, 0.65, 1.0)
                                })
                                .overflow_hidden()
                                .truncate()
                                .child(frame.func_name.clone()),
                        ),
                )
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(hsla(0.6, 0.3, 0.5, 1.0))
                        .truncate()
                        .child(format!("ret: {:#010x}", frame.ret_addr)),
                ),
        );
    }
    list
}

fn render_column_headers() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .px(px(8.0))
        .py(px(3.0))
        .bg(hsla(0.0, 0.0, 0.11, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.19, 1.0))
        .child(div().w(px(4.0))) // modified dot space
        .child(div().w(px(10.0))) // pin space
        .child(
            div()
                .w(px(40.0))
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child("SCOPE"),
        )
        .child(
            div()
                .w(px(120.0))
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child("NAME"),
        )
        .child(
            div()
                .w(px(100.0))
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child("TYPE"),
        )
        .child(
            div()
                .w(px(80.0))
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child("LOCATION"),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child("VALUE"),
        )
}

fn render_pinned_section(pinned: &[Variable]) -> impl IntoElement {
    if pinned.is_empty() {
        return div().into_any_element();
    }
    let mut section = div()
        .flex()
        .flex_col()
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.18, 1.0));

    section = section.child(
        div()
            .px(px(8.0))
            .py(px(3.0))
            .bg(hsla(0.15, 0.15, 0.12, 1.0))
            .flex()
            .flex_row()
            .items_center()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(9.0))
                    .text_color(hsla(0.15, 0.6, 0.55, 1.0))
                    .child(crate::ui::widgets::icon::icon("diamond")),
            )
            .child(
                div()
                    .text_size(px(10.0))
                    .text_color(hsla(0.0, 0.0, 0.45, 1.0))
                    .truncate()
                    .child(format!("PINNED ({})", pinned.len())),
            ),
    );

    for var in pinned {
        section = section.child(render_var_row(var, false));
    }
    section.into_any_element()
}

fn render_stack_info(state: &VariablesPanelState) -> impl IntoElement {
    let Some(frame) = state.current_frame() else {
        return div().into_any_element();
    };
    let total = state.total_stack_size();
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(12.0))
        .px(px(10.0))
        .py(px(3.0))
        .bg(hsla(0.0, 0.0, 0.07, 1.0))
        .border_t_1()
        .border_color(hsla(0.0, 0.0, 0.16, 1.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.6, 0.4, 0.55, 1.0))
                .truncate()
                .child(format!("frame base: {:#010x}", frame.frame_base)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.38, 1.0))
                .truncate()
                .child(format!("stack: {total} bytes")),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.0))
                .text_color(hsla(0.0, 0.0, 0.35, 1.0))
                .truncate()
                .child(format!("{} vars", frame.variables.len())),
        )
        .into_any_element()
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
                .text_size(px(28.0))
                .text_color(hsla(0.0, 0.0, 0.2, 1.0))
                .truncate()
                .child("x"),
        )
        .child(
            div()
                .text_size(px(13.0))
                .text_color(hsla(0.0, 0.0, 0.32, 1.0))
                .truncate()
                .child("No frame selected"),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(hsla(0.0, 0.0, 0.25, 1.0))
                .truncate()
                .child("Attach a debugger to inspect variables"),
        )
}

// ─── Main render ─────────────────────────────────────────────────────────────

pub fn render_variables_panel(
    state: &VariablesPanelState,
    _ui: Arc<Mutex<UIState>>,
) -> impl IntoElement {
    let visible = state.visible_vars();
    let has_frames = !state.frames.is_empty();

    div()
        .flex()
        .flex_col()
        .size_full()
        .bg(hsla(0.0, 0.0, 0.08, 1.0))
        .font_family("JetBrains Mono")
        // Toolbar
        .child(
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
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(hsla(0.0, 0.0, 0.45, 1.0))
                        .truncate()
                        .child("VARIABLES"),
                )
                .child(div().flex_1())
                // Filter toggles
                .child(filter_toggle("Params", state.show.params()))
                .child(filter_toggle("Locals", state.show.locals()))
                .child(filter_toggle("Regs", state.show.registers()))
                .child(filter_toggle("Modified", state.show.modified_only()))
                // Sort buttons
                .child(
                    div()
                        .h(px(14.0))
                        .w(px(1.0))
                        .bg(hsla(0.0, 0.0, 0.22, 1.0))
                        .mx(px(3.0)),
                )
                .child(sort_btn("Name", state.sort == VarSort::Name))
                .child(sort_btn("Type", state.sort == VarSort::Type))
                .child(sort_btn("Offs", state.sort == VarSort::Offset)),
        )
        // Body (frame list + variable list)
        .child(
            div()
                .flex()
                .flex_row()
                .flex_1()
                .overflow_hidden()
                // Frame list (left)
                .child(if state.show.frame_list() && has_frames {
                    render_frame_list(state).into_any_element()
                } else {
                    div().into_any_element()
                })
                // Main variable area (right)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .overflow_hidden()
                        .child(if has_frames {
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .overflow_hidden()
                                // Pinned vars section
                                .child(render_pinned_section(&state.pinned_vars))
                                // Column header
                                .child(render_column_headers())
                                // Variable rows
                                .child(div().flex().flex_col().flex_1().overflow_hidden().children(
                                    visible.iter().map(|v| {
                                        let selected = state.selected_var == Some(v.id);
                                        render_var_row(v, selected)
                                    }),
                                ))
                                .into_any_element()
                        } else {
                            render_empty_state().into_any_element()
                        }),
                ),
        )
        // Status bar
        .child(render_stack_info(state))
}

// ── prod ensure-used (mirrors tests; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_variables() {
    // VarScope: all variants + label + color
    let scopes = [
        VarScope::Local,
        VarScope::Parameter,
        VarScope::Global,
        VarScope::Register,
        VarScope::Temporary,
    ];
    for s in scopes {
        let _ = s.label();
        let _ = s.color();
    }

    // VarLocation: all variants + display
    let loc_stack_neg = VarLocation::StackOffset(-16);
    let loc_stack_pos = VarLocation::StackOffset(8);
    let loc_reg = VarLocation::Register("rax".to_string());
    let loc_global = VarLocation::GlobalAddr(0x0040_4000);
    let loc_composite = VarLocation::Composite(vec![
        VarLocation::Register("rdx".to_string()),
        VarLocation::StackOffset(-8),
    ]);
    let _ = loc_stack_neg.display();
    let _ = loc_stack_pos.display();
    let _ = loc_reg.display();
    let _ = loc_global.display();
    let _ = loc_composite.display();

    // VarValue: all variants + display + is_known + as_u64
    let v_unknown = VarValue::Unknown;
    let v_unavail = VarValue::Unavailable;
    let v_u64 = VarValue::U64(0x1234);
    let v_signed = VarValue::I64(-42);
    let v_float = VarValue::F64(std::f64::consts::PI);
    let v_bytes = VarValue::Bytes(vec![0xDE, 0xAD]);
    let v_ptr = VarValue::Pointer {
        addr: 0x0040_1000,
        deref: Some(Box::new(VarValue::U64(7))),
    };
    let v_ptr_none = VarValue::Pointer {
        addr: 0x0040_1000,
        deref: None,
    };
    let v_struct = VarValue::Struct(vec![("f".to_string(), VarValue::U64(1))]);
    let v_array = VarValue::Array(vec![VarValue::U64(1), VarValue::U64(2)]);
    let v_string = VarValue::String("hello".to_string());
    for vv in [
        &v_unknown,
        &v_unavail,
        &v_u64,
        &v_signed,
        &v_float,
        &v_bytes,
        &v_ptr,
        &v_ptr_none,
        &v_struct,
        &v_array,
        &v_string,
    ] {
        let _ = vv.display();
        let _ = vv.is_known();
        let _ = vv.as_u64();
    }

    // Variable::new
    let mut var1 = Variable::new(
        1,
        "arg1",
        "int",
        VarScope::Parameter,
        VarLocation::StackOffset(16),
    );
    var1.value = VarValue::U64(0xDEAD);
    var1.is_modified = true;
    var1.is_pinned = true;
    var1.size_bytes = 4;
    var1.notes = "n".to_string();
    var1.live_range = Some((0x0040_0000, 0x0040_0100));
    let var2 = Variable::new(
        2,
        "local_counter",
        "int",
        VarScope::Local,
        VarLocation::StackOffset(-8),
    );
    let var3 = Variable::new(
        3,
        "rax_val",
        "u64",
        VarScope::Register,
        VarLocation::Register("rax".to_string()),
    );

    // StackFrame + methods
    let frame = StackFrame {
        frame_index: 0,
        func_addr: 0x0040_1000,
        func_name: "test_func".to_string(),
        ret_addr: 0x0040_1100,
        frame_base: 0x7ffd_0000,
        variables: vec![var1.clone(), var2, var3],
        is_current: true,
    };
    let _ = frame.param_vars().count();
    let _ = frame.local_vars().count();
    let _ = frame.reg_vars().count();
    let _ = frame.frame_index;
    let _ = frame.func_addr;

    // VarSort: all variants + label
    for srt in [
        VarSort::Name,
        VarSort::Type,
        VarSort::Offset,
        VarSort::Scope,
    ] {
        let _ = srt.label();
    }

    // VariablesPanelState: default + fields + methods
    let mut state = VariablesPanelState::default();
    state.frames.push(frame);
    state.selected_frame = 0;
    state.selected_var = Some(1);
    state.sort = VarSort::Name;
    state.filter = "local".to_string();
    state.show.set(ShowFlag::Params, true);
    state.show.set(ShowFlag::Locals, true);
    state.show.set(ShowFlag::Registers, true);
    state.show.set(ShowFlag::ModifiedOnly, false);
    state.show.set(ShowFlag::FrameList, true);
    state.expanded_structs.insert(1);
    state.pinned_vars.push(var1.clone());
    let _ = state.current_frame();
    let _ = state.visible_vars();
    let _ = state.total_stack_size();

    // Render helpers
    let _ = scope_badge(VarScope::Local);
    let _ = sort_btn("Name", true);
    let _ = filter_toggle("Params", true);
    let _ = render_value_cell(&var1.value, var1.is_modified);
    let _ = render_var_row(&var1, true);
    let _ = render_frame_list(&state);
    let _ = render_column_headers();
    let _ = render_pinned_section(&state.pinned_vars);
    let _ = render_stack_info(&state);
    let _ = render_empty_state();

    // Main render
    let ui = Arc::new(Mutex::new(UIState::default()));
    let _ = render_variables_panel(&state, ui);
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(vars: Vec<Variable>) -> StackFrame {
        StackFrame {
            frame_index: 0,
            func_addr: 0x0040_1000,
            func_name: "test_func".to_string(),
            ret_addr: 0x0040_1100,
            frame_base: 0x7ffd_0000,
            variables: vars,
            is_current: true,
        }
    }

    fn make_var(id: u64, name: &str, scope: VarScope, off: i64) -> Variable {
        let mut v = Variable::new(id, name, "int", scope, VarLocation::StackOffset(off));
        v.value = VarValue::U64(0xDEAD);
        v
    }

    #[test]
    fn test_visible_vars_scope_filter() {
        let mut state = VariablesPanelState::default();
        state.frames.push(make_frame(vec![
            make_var(1, "arg1", VarScope::Parameter, 16),
            make_var(2, "local1", VarScope::Local, -8),
            make_var(3, "rax_val", VarScope::Register, 0),
        ]));
        state.show.set(ShowFlag::Params, false);
        let visible = state.visible_vars();
        assert!(visible.iter().all(|v| v.scope != VarScope::Parameter));
    }

    #[test]
    fn test_visible_vars_filter_text() {
        let mut state = VariablesPanelState::default();
        state.frames.push(make_frame(vec![
            make_var(1, "arg1", VarScope::Parameter, 16),
            make_var(2, "local_counter", VarScope::Local, -8),
        ]));
        state.filter = "local".to_string();
        let visible = state.visible_vars();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "local_counter");
    }

    #[test]
    fn test_visible_vars_sort_name() {
        let mut state = VariablesPanelState::default();
        state.frames.push(make_frame(vec![
            make_var(1, "zzz", VarScope::Local, -8),
            make_var(2, "aaa", VarScope::Local, -16),
        ]));
        state.sort = VarSort::Name;
        let visible = state.visible_vars();
        assert_eq!(visible[0].name, "aaa");
        assert_eq!(visible[1].name, "zzz");
    }

    #[test]
    fn test_visible_vars_modified_only() {
        let mut state = VariablesPanelState::default();
        let mut v1 = make_var(1, "a", VarScope::Local, -8);
        let v2 = make_var(2, "b", VarScope::Local, -16);
        v1.is_modified = true;
        state.frames.push(make_frame(vec![v1, v2]));
        state.show.set(ShowFlag::ModifiedOnly, true);
        let visible = state.visible_vars();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "a");
    }

    #[test]
    fn test_total_stack_size() {
        let mut state = VariablesPanelState::default();
        state.frames.push(make_frame(vec![
            make_var(1, "a", VarScope::Local, -8),
            make_var(2, "b", VarScope::Local, -32),
        ]));
        assert_eq!(state.total_stack_size(), 32);
    }

    #[test]
    fn test_var_value_display() {
        assert_eq!(VarValue::U64(0x1234).display(), "0x1234 (4660)");
        assert_eq!(VarValue::Unknown.display(), "<unknown>");
        assert_eq!(
            VarValue::Pointer {
                addr: 0x0040_1000,
                deref: None
            }
            .display(),
            "0x00401000"
        );
        assert_eq!(VarValue::String("hello".into()).display(), "\"hello\"");
    }

    #[test]
    fn test_var_location_display() {
        assert_eq!(VarLocation::StackOffset(-16).display(), "[rbp-0x10]");
        assert_eq!(VarLocation::StackOffset(8).display(), "[rbp+0x8]");
        assert_eq!(VarLocation::Register("rax".into()).display(), "rax");
        assert_eq!(VarLocation::GlobalAddr(0x0040_4000).display(), "0x00404000");
    }

    #[test]
    fn test_frame_iterator() {
        let frame = make_frame(vec![
            make_var(1, "p1", VarScope::Parameter, 16),
            make_var(2, "l1", VarScope::Local, -8),
            make_var(3, "r1", VarScope::Register, 0),
        ]);
        assert_eq!(frame.param_vars().count(), 1);
        assert_eq!(frame.local_vars().count(), 1);
        assert_eq!(frame.reg_vars().count(), 1);
    }
}
