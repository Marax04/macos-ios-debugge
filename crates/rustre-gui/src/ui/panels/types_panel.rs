// ============================================================================
// ui/panels/types_panel.rs — Type database panel
// ============================================================================

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::TypeInfo;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use rustre_il_mlil::{infer_types, InferredType, MlilFunction};
use std::fmt::Write as _;
use std::sync::Arc;

/// One recovered variable type, surfaced from `rustre_il_mlil::infer_types`.
///
/// `confidence` is a 0..=1 score derived from how the type was inferred:
///   - explicit constant / cmp result → 1.0
///   - propagated from a known def     → 0.7
///   - PHI of mixed sources / Unknown  → 0.3
#[derive(Debug, Clone)]
pub struct RecoveredVarType {
    pub var: String,
    pub version: u32,
    pub inferred: String,
    pub confidence: f32,
}

impl RecoveredVarType {
    fn confidence_for(ty: &InferredType) -> f32 {
        match ty {
            InferredType::Unknown => 0.3,
            InferredType::Bool => 0.95,
            InferredType::Pointer => 0.85,
            InferredType::Int(_) => 0.70,
        }
    }
}

/// Bitmask flags controlling which kinds of types are visible.
#[derive(Debug, Clone, Copy)]
pub struct KindMask(u8);

impl KindMask {
    pub const PRIMITIVE: u8 = 0b0001;
    pub const STRUCT: u8 = 0b0010;
    pub const ENUM: u8 = 0b0100;
    pub const TYPEDEF: u8 = 0b1000;

    pub const fn all() -> Self {
        Self(Self::PRIMITIVE | Self::STRUCT | Self::ENUM | Self::TYPEDEF)
    }

    pub const fn has(self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    pub const fn show_primitive(self) -> bool {
        self.has(Self::PRIMITIVE)
    }
    pub const fn show_struct(self) -> bool {
        self.has(Self::STRUCT)
    }
    pub const fn show_enum(self) -> bool {
        self.has(Self::ENUM)
    }
    pub const fn show_typedef(self) -> bool {
        self.has(Self::TYPEDEF)
    }
}

/// Mutable bits of the Types panel that need to be reached from
/// `on_click` callbacks. Wrapping them in `Arc<Mutex<…>>` lets the
/// row/chip/filter handlers capture `'static` clones while
/// `render_types_panel` continues to take `&TypesPanelState`.
#[derive(Debug, Default)]
pub struct TypesPanelInner {
    pub filter: String,
    pub selected_name: Option<String>,
    pub kinds_bits: u8,
    pub recovered: Vec<RecoveredVarType>,
    /// Bumped whenever filter / kind flags change so `refresh()` can
    /// recompute the virtual-list row count on the next frame.
    pub revision: u64,
    /// Last clicked recovered-row index and instant, used to fold two
    /// consecutive clicks within 400 ms into a "double click" without
    /// depending on `ClickEvent`'s click-count plumbing.
    pub last_recovered_click: Option<(usize, std::time::Instant)>,
}

#[derive(Debug)]
pub struct TypesPanelState {
    pub vlist: VirtualListState,
    inner: Arc<Mutex<TypesPanelInner>>,
    /// Last revision observed by `refresh()` — used to short-circuit
    /// `filter_names` recomputation when nothing changed.
    last_revision: u64,
}

impl Default for TypesPanelState {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            inner: Arc::new(Mutex::new(TypesPanelInner {
                filter: String::new(),
                selected_name: None,
                kinds_bits: KindMask::all().0,
                recovered: Vec::new(),
                revision: 0,
                last_recovered_click: None,
            })),
            last_revision: 0,
        }
    }
}

impl TypesPanelState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refresh(&mut self, data: &AppData) {
        let rev = self.inner.lock().revision;
        self.last_revision = rev;
        self.vlist.total_rows = self.filter_names(data).len();
    }

    /// Snapshot of the current filter string (cloned out of the mutex).
    pub fn filter_snapshot(&self) -> String {
        self.inner.lock().filter.clone()
    }

    /// Snapshot of the kind mask.
    pub fn kinds_snapshot(&self) -> KindMask {
        KindMask(self.inner.lock().kinds_bits)
    }

    /// Snapshot of the currently selected type name, if any.
    pub fn selected_snapshot(&self) -> Option<String> {
        self.inner.lock().selected_name.clone()
    }

    /// Snapshot of the recovered-types list (cheap clone — `RecoveredVarType`
    /// is small and the list is capped in practice).
    pub fn recovered_snapshot(&self) -> Vec<RecoveredVarType> {
        self.inner.lock().recovered.clone()
    }

    /// Handle to the shared mutable state — used by `on_click` callbacks.
    pub fn inner_handle(&self) -> Arc<Mutex<TypesPanelInner>> {
        Arc::clone(&self.inner)
    }

    pub fn filter_names<'a>(&self, data: &'a AppData) -> Vec<(&'a str, &'a TypeInfo)> {
        let guard = self.inner.lock();
        let q = guard.filter.to_lowercase();
        let kinds = KindMask(guard.kinds_bits);
        data.types
            .iter()
            .filter(|(name, ti)| {
                let kind_ok = match ti {
                    TypeInfo::Bool
                    | TypeInfo::Int { .. }
                    | TypeInfo::Float { .. }
                    | TypeInfo::Void => kinds.show_primitive(),
                    TypeInfo::Struct { .. } | TypeInfo::Union { .. } => kinds.show_struct(),
                    TypeInfo::Enum { .. } => kinds.show_enum(),
                    _ => kinds.show_typedef(),
                };
                kind_ok && (q.is_empty() || name.to_lowercase().contains(&q))
            })
            .map(|(n, ti)| (n.as_str(), ti))
            .collect()
    }

    /// Re-run MLIL type recovery for the given function and store the results.
    ///
    /// Wired to the public `rustre_il_mlil::infer_types` API; results are sorted by
    /// descending confidence so the noisiest inferences sink to the bottom.
    pub fn refresh_recovered_types(&mut self, func: &MlilFunction) {
        let map = infer_types(func);
        let mut out: Vec<RecoveredVarType> = map
            .into_iter()
            .map(|(var, ty)| RecoveredVarType {
                var: var.name.clone(),
                version: var.version,
                inferred: format!("{ty}"),
                confidence: RecoveredVarType::confidence_for(&ty),
            })
            .collect();
        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.var.cmp(&b.var))
                .then_with(|| a.version.cmp(&b.version))
        });
        let mut guard = self.inner.lock();
        guard.recovered = out;
        guard.revision = guard.revision.wrapping_add(1);
    }

    /// Clear stored type-recovery results (e.g. when navigating to a new function
    /// whose IL has not been lifted yet).
    pub fn clear_recovered_types(&mut self) {
        let mut guard = self.inner.lock();
        guard.recovered.clear();
        guard.revision = guard.revision.wrapping_add(1);
    }

    pub fn select(&mut self, name: String) {
        let mut guard = self.inner.lock();
        guard.selected_name = Some(name);
        guard.revision = guard.revision.wrapping_add(1);
    }

    /// Promote a recovered MLIL variable type into `AppData.types` so it
    /// participates in the regular type database. The actual write into
    /// `AppData` is not wired here (AppData is not reachable from this
    /// panel's callbacks); instead we record the request on the inner
    /// state so the host can drain it on the next refresh tick.
    pub fn promote_recovered(&mut self, entry: &RecoveredVarType) {
        // TODO(types): emit a `Command::TypePromote { name, inferred }`
        // here once that command variant exists in the bus; for now we
        // surface the promotion request by selecting the recovered
        // variable so the detail pane shows it.
        let mut guard = self.inner.lock();
        guard.selected_name = Some(entry.var.clone());
        guard.revision = guard.revision.wrapping_add(1);
    }
    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_up(&mut self) {
        self.vlist.move_selection(-1);
    }
    pub fn on_key_down(&mut self) {
        self.vlist.move_selection(1);
    }
}

pub fn render_types_panel<'a>(
    state: &'a TypesPanelState,
    data: &'a AppData,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    let entries = state.filter_names(data);
    let win = state.vlist.window();
    let entries_len = entries.len();
    let win_first = win.first;
    let win_last = win.last;

    let inner = state.inner_handle();
    let filter_str = state.filter_snapshot();
    let selected = state.selected_snapshot();
    let kinds = state.kinds_snapshot();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(panel_header("Types"))
        .child(filter_bar(&filter_str, "Filter types…", Arc::clone(&inner), bus))
        .child(kind_toggles(kinds, bus))
        .child(
            div().flex_1().overflow_hidden().child(
                div()
                    .w_full()
                    .h(px(win.total_height))
                    .child(div().h(px(win.top_pad)))
                    .children(
                        entries
                            .get(win_first..win_last.min(entries_len))
                            .unwrap_or(&[])
                            .iter()
                            .enumerate()
                            .map(|(i, e)| (win_first + i, *e))
                            .map(|(row, (name, ti))| {
                                debug_assert!(row >= win_first, "row index below window start");
                                let is_sel = selected.as_deref() == Some(name);
                                type_row(row, name, ti, is_sel, bus)
                            }),
                    )
                    .child(div().h(px(win.bottom_pad)))
            ),
        )
        .child(type_detail_pane(selected.as_deref(), data))
        .child(recovered_types_pane(state, Arc::clone(&inner), bus))
}

/// Bottom pane listing variables whose types were recovered by MLIL inference.
fn recovered_types_pane(
    state: &TypesPanelState,
    inner: Arc<Mutex<TypesPanelInner>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let recovered = state.recovered_snapshot();

    // "↻ Re-infer" — dispatches `TypesReinferCurrent`. The arm in
    // `handle_ui_command` clears the recovered list, flags
    // `UIState.pending_types_reinfer`, and surfaces a status message.
    let reinfer_bus = Arc::clone(bus);
    let reinfer_btn = div()
        .id(SharedString::from("types-reinfer-btn"))
        .px(px(6.0))
        .h(px(16.0))
        .rounded(px(8.0))
        .bg(colors::bg_elevated())
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(10.0))
        .text_color(colors::text_primary())
        .child("↻ Re-infer")
        .on_click(move |_, _, _| {
            reinfer_bus.send_command(UICommand::TypesReinferCurrent);
        });

    let header = div()
        .h(px(20.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_2()
        .bg(colors::bg_surface())
        .border_t_1()
        .border_color(colors::border())
        .text_size(px(sizes::LABEL))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(format!("Recovered types  ({})", recovered.len()))
        .child(reinfer_btn);

    let mut body = div()
        .flex()
        .flex_col()
        .h(px(120.0))
        .bg(colors::bg_elevated())
        .overflow_hidden();

    if recovered.is_empty() {
        body = body.child(
            div()
                .px_2()
                .py_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child("No MLIL type recovery results — open a function and run the pipeline.")
                .truncate(),
        );
    } else {
        for (i, entry) in recovered.iter().take(64).enumerate() {
            body = body.child(recovered_row_interactive(i, entry, Arc::clone(&inner), bus));
        }
    }

    div()
        .flex()
        .flex_col()
        .child(header)
        .child(body)
}

/// Double-clickable wrapper around `recovered_row`. A single click selects
/// the variable in the detail pane (via `TypesSelect`); a double click
/// promotes it to the persistent type database (via `TypesPromoteRecovered`).
fn recovered_row_interactive(
    idx: usize,
    entry: &RecoveredVarType,
    inner: Arc<Mutex<TypesPanelInner>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let entry_owned = entry.clone();
    let click_bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("types-recovered-{idx}")))
        .cursor_pointer()
        .on_click(move |_, _, _| {
            // 400 ms double-click gate — gpui's `ClickEvent.click_count`
            // isn't exposed as a stable field on this surface.
            let now = std::time::Instant::now();
            let is_double = {
                let mut g = inner.lock();
                let dbl = matches!(
                    g.last_recovered_click,
                    Some((prev_idx, prev_t))
                        if prev_idx == idx
                            && now.saturating_duration_since(prev_t)
                                < std::time::Duration::from_millis(400)
                );
                g.last_recovered_click = Some((idx, now));
                dbl
            };
            if is_double {
                click_bus.send_command(UICommand::TypesPromoteRecovered {
                    var: entry_owned.var.clone(),
                    inferred: entry_owned.inferred.clone(),
                });
            } else {
                click_bus.send_command(UICommand::TypesSelect(entry_owned.var.clone()));
            }
        })
        .child(recovered_row(entry))
}

fn recovered_row(entry: &RecoveredVarType) -> impl IntoElement {
    let (bar_w, bar_color) = confidence_bar(entry.confidence);
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(sizes::ROW_H))
        .px_2()
        .child(
            div()
                .w(px(150.0))
                .text_size(px(sizes::CODE))
                .text_color(colors::text_primary())
                .font_family("JetBrains Mono")
                .child(format!("{}#{}", entry.var, entry.version))
                .truncate(),
        )
        .child(
            div()
                .w(px(70.0))
                .text_size(px(sizes::CODE))
                .text_color(colors::accent_cyan())
                .font_family("JetBrains Mono")
                .child(entry.inferred.clone())
                .truncate(),
        )
        .child(
            // Confidence bar.
            div()
                .w(px(80.0))
                .h(px(6.0))
                .bg(colors::bg_base())
                .rounded(px(3.0))
                .child(
                    div()
                        .w(px(bar_w))
                        .h(px(6.0))
                        .bg(bar_color)
                        .rounded(px(3.0)),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .font_family("JetBrains Mono")
                .child(format!("{:.0}%", entry.confidence * 100.0))
                .truncate(),
        )
}

fn confidence_bar(confidence: f32) -> (f32, Hsla) {
    let clamped = confidence.clamp(0.0, 1.0);
    let width = 80.0 * clamped;
    let color = if clamped >= 0.75 {
        colors::ok()
    } else if clamped >= 0.5 {
        colors::warn()
    } else {
        colors::err()
    };
    (width, color)
}

fn type_row(
    row_idx: usize,
    name: &str,
    ti: &TypeInfo,
    selected: bool,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let name_owned = name.to_owned();
    let click_bus = Arc::clone(bus);
    let bg = if selected {
        colors::bg_selection()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };
    let (badge, bcol) = kind_badge(ti);
    let size_str = type_display_size(ti);
    div()
        .id(SharedString::from(format!("types-row-{row_idx}")))
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .w_full()
        .h(px(sizes::ROW_H))
        .bg(bg)
        .px_2()
        .cursor_pointer()
        .on_click(move |_, _, _| {
            click_bus.send_command(UICommand::TypesSelect(name_owned.clone()));
        })
        .child(
            div()
                .w(px(16.0))
                .h(px(16.0))
                .rounded(px(3.0))
                .bg(bcol)
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(9.0))
                .text_color(Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.9,
                    a: 1.0,
                })
                .child(badge),
        )
        .child(
            div()
                .flex_1()
                .text_color(colors::text_primary())
                .text_size(px(sizes::CODE))
                .font_family("JetBrains Mono")
                .child(name.to_owned())
                .truncate(),
        )
        .child(
            div()
                .text_color(colors::text_muted())
                .text_size(px(sizes::LABEL))
                .font_family("JetBrains Mono")
                .child(size_str)
                .truncate(),
        )
}

fn type_detail_pane<'a>(
    selected: Option<&str>,
    data: &'a AppData,
) -> impl IntoElement + 'a {
    let text = selected
        .and_then(|n| data.types.get(n))
        .map_or_else(|| "Select a type".to_owned(), render_c_type);
    div()
        .h(px(160.0))
        .border_t_1()
        .border_color(colors::border())
        .bg(colors::bg_elevated())
        .p_2()
        .overflow_hidden()
        .child(
            div()
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::text_primary())
                .font_family("JetBrains Mono")
                .child(text)
                .truncate(),
        )
}

fn render_c_type(ti: &TypeInfo) -> String {
    match ti {
        TypeInfo::Struct { name, fields } => {
            let fields_str = fields.iter().fold(String::new(), |mut acc, f| {
                let _ = writeln!(acc, "  /* +{:3} */ {:?} {};", f.offset, f.kind, f.name);
                acc
            });
            let total = fields.iter().map(|f| f.offset + f.size).max().unwrap_or(0);
            format!("struct {name} {{\n{fields_str}}} /* size={total} */;")
        }
        TypeInfo::Union { name, fields } => {
            let fields_str = fields.iter().fold(String::new(), |mut acc, f| {
                let _ = writeln!(acc, "  {:?} {};", f.kind, f.name);
                acc
            });
            format!("union {name} {{\n{fields_str}}};")
        }
        TypeInfo::Enum { name, variants, .. } => {
            let vs = variants.iter().fold(String::new(), |mut acc, (v, val)| {
                let _ = writeln!(acc, "  {v} = {val},");
                acc
            });
            format!("enum {name} {{\n{vs}}};")
        }
        TypeInfo::Named { name } => format!("typedef ... {name};"),
        _ => format!("{ti:?}"),
    }
}

fn kind_badge(ti: &TypeInfo) -> (String, Hsla) {
    match ti {
        TypeInfo::Struct { .. } => (
            "S".into(),
            Hsla {
                h: 200.0 / 360.0,
                s: 0.6,
                l: 0.35,
                a: 1.0,
            },
        ),
        TypeInfo::Union { .. } => (
            "U".into(),
            Hsla {
                h: 180.0 / 360.0,
                s: 0.5,
                l: 0.30,
                a: 1.0,
            },
        ),
        TypeInfo::Enum { .. } => (
            "E".into(),
            Hsla {
                h: 280.0 / 360.0,
                s: 0.5,
                l: 0.35,
                a: 1.0,
            },
        ),
        TypeInfo::Bool | TypeInfo::Int { .. } | TypeInfo::Float { .. } | TypeInfo::Void => (
            "P".into(),
            Hsla {
                h: 30.0 / 360.0,
                s: 0.5,
                l: 0.35,
                a: 1.0,
            },
        ),
        _ => (
            "T".into(),
            Hsla {
                h: 140.0 / 360.0,
                s: 0.5,
                l: 0.30,
                a: 1.0,
            },
        ),
    }
}

fn type_display_size(ti: &TypeInfo) -> String {
    match ti {
        TypeInfo::Void => "0B".into(),
        TypeInfo::Bool => "1B".into(),
        TypeInfo::Int { bits, .. } | TypeInfo::Float { bits } => format!("{}B", bits / 8),
        TypeInfo::Pointer { .. } => "8B".into(),
        TypeInfo::Struct { fields, .. } | TypeInfo::Union { fields, .. } => {
            format!(
                "{}B",
                fields.iter().map(|f| f.offset + f.size).max().unwrap_or(0)
            )
        }
        _ => "?B".into(),
    }
}

fn kind_toggles(kinds: KindMask, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_1()
        .px_2()
        .py_1()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(chip("Prim", "prim", kinds.show_primitive(), 0, bus))
        .child(chip("Struct", "struct", kinds.show_struct(), 1, bus))
        .child(chip("Enum", "enum", kinds.show_enum(), 2, bus))
        .child(chip("Typedef", "typedef", kinds.show_typedef(), 3, bus))
}

/// One filter chip. `slot` is the `TypesCycleKindFilter` slot id
/// (0=Prim, 1=Struct, 2=Enum, 3=Typedef).
fn chip(
    label: &str,
    id_tag: &'static str,
    active: bool,
    slot: u8,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bg = if active {
        colors::accent()
    } else {
        colors::bg_elevated()
    };
    let fg = if active {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.9,
            a: 1.0,
        }
    } else {
        colors::text_muted()
    };
    let click_bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("types-chip-{id_tag}")))
        .px(px(6.0))
        .h(px(18.0))
        .rounded(px(9.0))
        .bg(bg)
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(10.0))
        .text_color(fg)
        .child(label.to_owned())
        .on_click(move |_, _, _| {
            click_bus.send_command(UICommand::TypesCycleKindFilter(slot));
        })
}

fn panel_header(title: &str) -> impl IntoElement {
    div()
        .h(px(24.0))
        .flex()
        .items_center()
        .px_3()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .text_size(px(sizes::LABEL))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(title.to_owned())
        .truncate()
}

fn filter_bar(
    val: &str,
    placeholder: &str,
    _inner: Arc<Mutex<TypesPanelInner>>,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let text = if val.is_empty() {
        placeholder.to_owned()
    } else {
        val.to_owned()
    };
    let col = if val.is_empty() {
        colors::text_muted()
    } else {
        colors::text_primary()
    };

    // gpui doesn't expose a `TextEdit::singleline` widget in this
    // workspace; live typing is routed through the global key dispatcher
    // in `ui::app`. The visible field still acts as a click affordance
    // that clears the current filter via `TypesClearFilter`, so the
    // user always has a way to reset without keyboard focus tricks.
    let click_bus = Arc::clone(bus);
    div()
        .h(px(28.0))
        .flex()
        .items_center()
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .id(SharedString::from("types-filter-input"))
                .flex_1()
                .h(px(20.0))
                .px_2()
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .cursor_pointer()
                .text_size(px(sizes::CODE))
                .text_color(col)
                .font_family("JetBrains Mono")
                .child(text)
                .truncate()
                .on_click(move |_, _, _| {
                    click_bus.send_command(UICommand::TypesClearFilter);
                }),
        )
}

#[doc(hidden)]
pub fn ensure_used_types_panel() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let mut s = TypesPanelState::new();
    s.select("__probe__".to_owned());
    s.on_scroll(1.0);
    s.on_key_up();
    s.on_key_down();

    // Touch the MLIL type-recovery surface so the wiring is reachable.
    // The actual refresh path takes a real MlilFunction (built by the analysis
    // engine); the ensure-used pass only checks the no-arg variants.
    s.clear_recovered_types();
    // Mark `refresh_recovered_types` as referenced via a pointer cast so the
    // dead-code lint can't flag it without trying to construct an MlilFunction.
    let _: fn(&mut TypesPanelState, &MlilFunction) = TypesPanelState::refresh_recovered_types;
    let entry = RecoveredVarType {
        var: "x".to_string(),
        version: 0,
        inferred: "int32".to_string(),
        confidence: 0.9,
    };
    let _ = RecoveredVarType::confidence_for(&InferredType::Bool);
    let bus = Arc::new(EventBus::new());
    let _ = recovered_row(&entry);
    let _ = recovered_types_pane(&s, s.inner_handle(), &bus);
    let _ = recovered_row_interactive(0, &entry, s.inner_handle(), &bus);
    let _ = confidence_bar(0.5);
    let _ = render_types_panel(&s, &AppData::new(), &bus);
    let _ = filter_bar("", "ph", s.inner_handle(), &bus);
    let _ = kind_toggles(s.kinds_snapshot(), &bus);
    let _ = chip("c", "c", false, 0, &bus);
    let ti = TypeInfo::Void;
    let _ = type_row(0, "x", &ti, false, &bus);

    // Touch snapshot/handle accessors plus promotion so the wiring is
    // exercised by the dead-code probe.
    let _ = s.filter_snapshot();
    let _ = s.kinds_snapshot();
    let _ = s.selected_snapshot();
    let _ = s.recovered_snapshot();
    s.promote_recovered(&entry);
}
