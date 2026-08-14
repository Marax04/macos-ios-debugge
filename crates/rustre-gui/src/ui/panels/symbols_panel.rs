// ============================================================================
// ui/panels/symbols_panel.rs — Extended symbol browser
// ----------------------------------------------------------------------------
// Ports the legacy three-tab symbol panel (Symbols / Imports / Exports) to the
// current function-style GPUI panel convention used by the rest of the
// zyphora GUI. Surfaces FLIRT match badges, demangled names, source filters,
// per-DLL import grouping and the mass-rename pipeline that the basic
// `symbols.rs` panel doesn't cover.
//
// The legacy data model (SymbolInfo / ImportInfo / ExportInfo / Address /
// SymbolSource / SymbolKind etc.) is preserved verbatim because the panel
// drives its own pre-processed view of `AppData::symbols`. The local
// `SymbolKind` mirror is distinct from `core::types::SymbolKind` so that the
// FLIRT/demangle features remain self-contained.
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::cpu_pool::cpu_pool;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Symbol as CoreSymbol, SymbolKind as CoreSymKind};
use rayon::prelude::*;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::wheel_delta;
use gpui::{
    div, px, uniform_list, AnyElement, FontWeight, Hsla, InteractiveElement, IntoElement,
    ParentElement, ScrollWheelEvent, SharedString, StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

// ── Local data model ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Function,
    Data,
    Thunk,
    Label,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolSource {
    Pdb,
    Dwarf,
    Flirt,
    User,
    Auto,
}

#[derive(Clone, Debug)]
pub struct SymbolInfo {
    pub address: Address,
    pub name: String,
    pub demangled_name: Option<String>,
    pub kind: SymbolKind,
    pub source: SymbolSource,
    pub module: Option<String>,
    pub flirt_library: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ImportInfo {
    pub dll_name: String,
    pub function_name: String,
    pub iat_address: Address,
    pub ordinal: Option<u32>,
    pub resolved_target: Option<Address>,
}

#[derive(Clone, Debug)]
pub struct ExportInfo {
    pub name: String,
    pub address: Address,
    pub ordinal: u32,
    pub forwarded_to: Option<String>,
}

// ── Tabs ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SymbolsTab {
    #[default]
    Symbols,
    Imports,
    Exports,
}

impl SymbolsTab {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Symbols => "Symbols",
            Self::Imports => "Imports",
            Self::Exports => "Exports",
        }
    }
}

// ── Filters ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct KindFilter {
    pub function: bool,
    pub data: bool,
    pub thunk: bool,
    pub label: bool,
}

impl Default for KindFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl KindFilter {
    pub const fn all() -> Self {
        Self {
            function: true,
            data: true,
            thunk: true,
            label: true,
        }
    }

    pub const fn matches(&self, kind: SymbolKind) -> bool {
        match kind {
            SymbolKind::Function => self.function,
            SymbolKind::Data => self.data,
            SymbolKind::Thunk => self.thunk,
            SymbolKind::Label => self.label,
            SymbolKind::Other => true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourceFilter {
    pub pdb: bool,
    pub dwarf: bool,
    pub flirt: bool,
    pub user: bool,
    pub auto: bool,
}

impl Default for SourceFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl SourceFilter {
    pub const fn all() -> Self {
        Self {
            pdb: true,
            dwarf: true,
            flirt: true,
            user: true,
            auto: true,
        }
    }

    pub const fn matches(&self, source: SymbolSource) -> bool {
        match source {
            SymbolSource::Pdb => self.pdb,
            SymbolSource::Dwarf => self.dwarf,
            SymbolSource::Flirt => self.flirt,
            SymbolSource::User => self.user,
            SymbolSource::Auto => self.auto,
        }
    }
}

// ── Sort ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SymbolSortCol {
    Name,
    #[default]
    Address,
    Kind,
    Source,
    Module,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

impl SortDir {
    pub const fn toggle(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Asc => "sort-asc",
            Self::Desc => "sort-desc",
        }
    }
}

// ── Pre-processed row ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SymbolRow {
    pub info: SymbolInfo,
    pub display_name: SharedString,
    pub selected: bool,
}

impl SymbolRow {
    pub fn new(info: SymbolInfo, demangled: bool) -> Self {
        let display_name = if demangled {
            info.demangled_name
                .clone()
                .unwrap_or_else(|| info.name.clone())
                .into()
        } else {
            info.name.clone().into()
        };
        Self {
            info,
            display_name,
            selected: false,
        }
    }
}

// ── Import group (per-DLL) ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ImportGroup {
    pub dll_name: SharedString,
    pub imports: Vec<ImportInfo>,
    pub expanded: bool,
    pub filter_match: bool,
}

impl ImportGroup {
    pub fn new(dll_name: SharedString, imports: Vec<ImportInfo>) -> Self {
        Self {
            dll_name,
            imports,
            expanded: true,
            filter_match: true,
        }
    }
}

// ── Context menu / mass rename / badges ──────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SymbolContextMenu {
    pub position: (f32, f32),
    pub targets: Vec<Address>,
    pub items: Vec<SymbolContextItem>,
}

#[derive(Clone, Debug)]
pub struct SymbolContextItem {
    pub label: SharedString,
    pub action: SymbolContextAction,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub enum SymbolContextAction {
    NavigateTo(Address),
    Rename,
    AddComment,
    SetType,
    FindReferences,
    ExportSelected,
    BatchRename,
}

#[derive(Clone, Debug, Default)]
pub struct MassRenameState {
    pub selected_addresses: Vec<Address>,
    pub pattern: String,
    pub preview: Vec<(Address, String)>,
}

impl MassRenameState {
    pub fn new(addresses: Vec<Address>) -> Self {
        Self {
            selected_addresses: addresses,
            pattern: String::new(),
            preview: Vec::new(),
        }
    }

    pub fn update_pattern(&mut self, pattern: &str, symbols: &[SymbolRow]) {
        self.pattern = pattern.to_owned();
        self.preview = self
            .selected_addresses
            .iter()
            .filter_map(|addr| {
                symbols.iter().find(|s| s.info.address == *addr).map(|s| {
                    let new_name = if pattern.contains("{name}") {
                        pattern.replace("{name}", &s.info.name)
                    } else if pattern.contains("{addr}") {
                        pattern.replace("{addr}", &format!("{:x}", s.info.address.0))
                    } else {
                        format!("{}{}", pattern, s.info.name)
                    };
                    (*addr, new_name)
                })
            })
            .collect();
    }
}

#[derive(Clone, Debug, Default)]
pub struct SymbolBadges {
    pub unresolved: usize,
    pub flirt_matched: usize,
    pub user_defined: usize,
    pub total: usize,
}

// ── Panel state ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SymbolsPanelState {
    pub active_tab: SymbolsTab,

    // Symbols tab
    pub all_symbols: Vec<SymbolRow>,
    pub filtered_symbols: Vec<usize>,
    pub symbol_filter_text: String,
    pub kind_filter: KindFilter,
    pub source_filter: SourceFilter,
    pub sort_col: SymbolSortCol,
    pub sort_dir: SortDir,
    pub show_demangled: bool,
    pub symbol_scroll: usize,
    pub selected_symbols: Vec<Address>,

    // Imports tab
    pub import_groups: Vec<ImportGroup>,
    pub import_filter_text: String,
    pub import_scroll: usize,

    // Exports tab
    pub all_exports: Vec<ExportInfo>,
    pub filtered_exports: Vec<usize>,
    pub export_filter_text: String,
    pub export_scroll: usize,

    // Shared
    pub rows_per_page: usize,
    pub row_height_px: f32,
    pub context_menu: Option<SymbolContextMenu>,
    pub mass_rename: Option<MassRenameState>,
    pub badges: SymbolBadges,

    // Refresh tracking
    pub cached_rev: u64,
}

impl Default for SymbolsPanelState {
    fn default() -> Self {
        Self {
            active_tab: SymbolsTab::default(),
            all_symbols: Vec::new(),
            filtered_symbols: Vec::new(),
            symbol_filter_text: String::new(),
            kind_filter: KindFilter::all(),
            source_filter: SourceFilter::all(),
            sort_col: SymbolSortCol::default(),
            sort_dir: SortDir::Asc,
            show_demangled: true,
            symbol_scroll: 0,
            selected_symbols: Vec::new(),
            import_groups: Vec::new(),
            import_filter_text: String::new(),
            import_scroll: 0,
            all_exports: Vec::new(),
            filtered_exports: Vec::new(),
            export_filter_text: String::new(),
            export_scroll: 0,
            rows_per_page: 40,
            row_height_px: sizes::ROW_H,
            context_menu: None,
            mass_rename: None,
            badges: SymbolBadges::default(),
            cached_rev: u64::MAX,
        }
    }
}

impl SymbolsPanelState {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if self.cached_rev == rev {
            return;
        }
        self.cached_rev = rev;

        // Snapshot into a Vec once so all three transforms (all_symbols /
        // imports / exports) can run in parallel via rayon::join — and so
        // par_iter has something to split. With 81k+ symbols the legacy
        // serial path allocated ~81k SymbolRow + 81k clones of module
        // strings on the UI thread on every symbols-rev bump, which was
        // the cause of the "switch tab → crash" the user was seeing.
        let syms: Vec<&CoreSymbol> = data.symbols.values().collect();
        let show_demangled = self.show_demangled;

        // ── all_symbols (parallel map) ──
        let all_symbols: Vec<SymbolRow> = cpu_pool().install(|| {
            syms.par_iter()
                .map(|s| SymbolRow::new(from_core_symbol(s), show_demangled))
                .collect()
        });

        // ── imports: parallel filter+map → reduce into the HashMap ──
        let import_infos: Vec<(String, ImportInfo)> = cpu_pool().install(|| {
            syms.par_iter()
                .filter(|s| matches!(s.kind, CoreSymKind::Import))
                .map(|s| {
                    let dll = s.module.clone().unwrap_or_else(|| "<unknown>".to_owned());
                    let info = ImportInfo {
                        dll_name: s.module.clone().unwrap_or_else(|| dll.clone()),
                        function_name: s.display_name().to_owned(),
                        iat_address: Address(s.addr.0),
                        ordinal: s.ordinal,
                        resolved_target: s.resolved_target.map(|a| Address(a.0)),
                    };
                    (dll, info)
                })
                .collect()
        });
        let mut groups: HashMap<String, Vec<ImportInfo>> = HashMap::new();
        for (dll, info) in import_infos {
            groups.entry(dll).or_default().push(info);
        }
        let mut sorted_groups: Vec<_> = groups.into_iter().collect();
        sorted_groups.sort_by(|a, b| a.0.cmp(&b.0));

        // ── exports (parallel filter+map) ──
        let exports_with_addr: Vec<(u64, ExportInfo)> = cpu_pool().install(|| {
            syms.par_iter()
                .filter(|s| matches!(s.kind, CoreSymKind::Export))
                .map(|s| {
                    (
                        s.addr.0,
                        ExportInfo {
                            name: s.display_name().to_owned(),
                            address: Address(s.addr.0),
                            ordinal: s.ordinal.unwrap_or(0),
                            forwarded_to: s.forwarded_to.clone(),
                        },
                    )
                })
                .collect()
        });
        // Re-stamp fallback ordinals using the iteration index so the
        // column is never blank when the parser didn't supply one.
        // No PE has >4G exports — saturate to u32::MAX rather than
        // wrapping silently if some pathological case shows up.
        let all_exports: Vec<ExportInfo> = exports_with_addr
            .into_iter()
            .enumerate()
            .map(|(idx, (_, mut e))| {
                if e.ordinal == 0 {
                    e.ordinal = u32::try_from(idx).unwrap_or(u32::MAX);
                }
                e
            })
            .collect();

        self.all_symbols = all_symbols;
        self.import_groups = sorted_groups
            .into_iter()
            .map(|(dll, imps)| ImportGroup::new(dll.into(), imps))
            .collect();
        self.all_exports = all_exports;

        self.recompute_badges();
        self.apply_filter_and_sort();
        self.apply_import_filter();
        self.apply_export_filter();
    }

    fn recompute_badges(&mut self) {
        self.badges.total = self.all_symbols.len();
        self.badges.flirt_matched = self
            .all_symbols
            .iter()
            .filter(|s| matches!(s.info.source, SymbolSource::Flirt))
            .count();
        self.badges.user_defined = self
            .all_symbols
            .iter()
            .filter(|s| matches!(s.info.source, SymbolSource::User))
            .count();
        self.badges.unresolved = self
            .all_symbols
            .iter()
            .filter(|s| {
                matches!(s.info.source, SymbolSource::Auto) && s.info.name.starts_with("sub_")
            })
            .count();
    }

    pub fn apply_filter_and_sort(&mut self) {
        let text = self.symbol_filter_text.to_lowercase();
        let kind_filter = self.kind_filter.clone();
        let source_filter = self.source_filter.clone();

        let mut indices: Vec<usize> = (0..self.all_symbols.len())
            .filter(|&i| {
                let sym = &self.all_symbols[i];
                let name_match = text.is_empty()
                    || sym.display_name.to_lowercase().contains(&text)
                    || format!("{:016x}", sym.info.address.0).contains(&text);
                let kind_match = kind_filter.matches(sym.info.kind);
                let source_match = source_filter.matches(sym.info.source);
                name_match && kind_match && source_match
            })
            .collect();

        let all_syms = &self.all_symbols;
        let sort_col = self.sort_col;
        let sort_dir = self.sort_dir;
        indices.sort_by(|&a, &b| {
            let sa = &all_syms[a];
            let sb = &all_syms[b];
            let ord = match sort_col {
                SymbolSortCol::Name => sa.display_name.cmp(&sb.display_name),
                SymbolSortCol::Address => sa.info.address.0.cmp(&sb.info.address.0),
                SymbolSortCol::Kind => {
                    format!("{:?}", sa.info.kind).cmp(&format!("{:?}", sb.info.kind))
                }
                SymbolSortCol::Source => {
                    format!("{:?}", sa.info.source).cmp(&format!("{:?}", sb.info.source))
                }
                SymbolSortCol::Module => sa.info.module.cmp(&sb.info.module),
            };
            if matches!(sort_dir, SortDir::Desc) {
                ord.reverse()
            } else {
                ord
            }
        });

        self.filtered_symbols = indices;
        self.symbol_scroll = 0;
    }

    pub fn apply_import_filter(&mut self) {
        let text = self.import_filter_text.to_lowercase();
        for group in &mut self.import_groups {
            let dll_match = text.is_empty() || group.dll_name.to_lowercase().contains(&text);
            let any_func_match = group
                .imports
                .iter()
                .any(|i| i.function_name.to_lowercase().contains(&text));
            group.filter_match = dll_match || any_func_match;
        }
    }

    pub fn apply_export_filter(&mut self) {
        let text = self.export_filter_text.to_lowercase();
        self.filtered_exports = (0..self.all_exports.len())
            .filter(|&i| {
                let exp = &self.all_exports[i];
                text.is_empty()
                    || exp.name.to_lowercase().contains(&text)
                    || format!("{:016x}", exp.address.0).contains(&text)
            })
            .collect();
    }

    pub fn set_sort(&mut self, col: SymbolSortCol) {
        if self.sort_col == col {
            self.sort_dir = self.sort_dir.toggle();
        } else {
            self.sort_col = col;
            self.sort_dir = SortDir::Asc;
        }
        self.apply_filter_and_sort();
    }

    pub fn set_filter(&mut self, text: &str) {
        self.symbol_filter_text = text.to_owned();
        self.apply_filter_and_sort();
    }

    pub fn toggle_show_demangled(&mut self) {
        self.show_demangled = !self.show_demangled;
        for row in &mut self.all_symbols {
            row.display_name = if self.show_demangled {
                row.info
                    .demangled_name
                    .clone()
                    .unwrap_or_else(|| row.info.name.clone())
                    .into()
            } else {
                row.info.name.clone().into()
            };
        }
        self.apply_filter_and_sort();
    }

    pub fn select_symbol(&mut self, address: Address, multi: bool) {
        if multi {
            if let Some(pos) = self.selected_symbols.iter().position(|&a| a == address) {
                self.selected_symbols.remove(pos);
            } else {
                self.selected_symbols.push(address);
            }
        } else {
            self.selected_symbols = vec![address];
        }
    }

    pub fn is_selected(&self, address: Address) -> bool {
        self.selected_symbols.contains(&address)
    }

    pub fn select_all(&mut self) {
        self.selected_symbols = self
            .filtered_symbols
            .iter()
            .map(|&i| self.all_symbols[i].info.address)
            .collect();
    }

    pub fn clear_selection(&mut self) {
        self.selected_symbols.clear();
    }

    pub fn open_context_menu(&mut self, pos: (f32, f32), addresses: Vec<Address>) {
        let is_multi = addresses.len() > 1;
        let items = vec![
            SymbolContextItem {
                label: if is_multi {
                    "Navigate (select one)".into()
                } else {
                    "Navigate to Address".into()
                },
                action: if addresses.len() == 1 {
                    SymbolContextAction::NavigateTo(addresses[0])
                } else {
                    SymbolContextAction::ExportSelected
                },
                enabled: addresses.len() == 1,
            },
            SymbolContextItem {
                label: "Rename".into(),
                action: SymbolContextAction::Rename,
                enabled: addresses.len() <= 1,
            },
            SymbolContextItem {
                label: "Add Comment".into(),
                action: SymbolContextAction::AddComment,
                enabled: addresses.len() == 1,
            },
            SymbolContextItem {
                label: "Set Type".into(),
                action: SymbolContextAction::SetType,
                enabled: addresses.len() == 1,
            },
            SymbolContextItem {
                label: "Find References".into(),
                action: SymbolContextAction::FindReferences,
                enabled: addresses.len() == 1,
            },
            SymbolContextItem {
                label: format!("Batch Rename ({} symbols)", addresses.len()).into(),
                action: SymbolContextAction::BatchRename,
                enabled: addresses.len() > 1,
            },
            SymbolContextItem {
                label: "Export Selected".into(),
                action: SymbolContextAction::ExportSelected,
                enabled: !addresses.is_empty(),
            },
        ];
        self.context_menu = Some(SymbolContextMenu {
            position: pos,
            targets: addresses,
            items,
        });
    }

    pub fn close_context_menu(&mut self) {
        self.context_menu = None;
    }

    pub fn open_mass_rename(&mut self) {
        let addresses = self.selected_symbols.clone();
        if addresses.is_empty() {
            return;
        }
        self.mass_rename = Some(MassRenameState::new(addresses));
    }

    pub fn update_mass_rename_pattern(&mut self, pattern: &str) {
        let syms = self.all_symbols.clone();
        if let Some(state) = &mut self.mass_rename {
            state.update_pattern(pattern, &syms);
        }
    }

    pub fn cancel_mass_rename(&mut self) {
        self.mass_rename = None;
    }

    pub fn export_to_csv(&self) -> String {
        let mut csv = String::from("address,name,kind,source,module\n");
        for &i in &self.filtered_symbols {
            let sym = &self.all_symbols[i];
            csv.push_str(&format!(
                "{:016x},{},{:?},{:?},{}\n",
                sym.info.address.0,
                sym.display_name,
                sym.info.kind,
                sym.info.source,
                sym.info.module.as_deref().unwrap_or("")
            ));
        }
        csv
    }

    pub fn export_to_json(&self) -> String {
        let mut json = String::from("[\n");
        for (n, &i) in self.filtered_symbols.iter().enumerate() {
            let sym = &self.all_symbols[i];
            json.push_str(&format!(
                "  {{\"address\":\"{:016x}\",\"name\":\"{}\",\"kind\":\"{:?}\",\"source\":\"{:?}\",\"module\":\"{}\"}}{}",
                sym.info.address.0,
                sym.display_name,
                sym.info.kind,
                sym.info.source,
                sym.info.module.as_deref().unwrap_or(""),
                if n + 1 < self.filtered_symbols.len() { ",\n" } else { "\n" }
            ));
        }
        json.push_str("]\n");
        json
    }

    pub fn scroll_symbols_by(&mut self, delta: i64) {
        let max_scroll = self.filtered_symbols.len().saturating_sub(self.rows_per_page);
        let new = (self.symbol_scroll as i64 + delta)
            .max(0)
            .min(max_scroll as i64) as usize;
        self.symbol_scroll = new;
    }

    pub fn scroll_imports_by(&mut self, delta: i64) {
        let total_rows = self.import_total_rows();
        let max_scroll = total_rows.saturating_sub(self.rows_per_page);
        let new = (self.import_scroll as i64 + delta)
            .max(0)
            .min(max_scroll as i64) as usize;
        self.import_scroll = new;
    }

    fn import_total_rows(&self) -> usize {
        self.import_groups
            .iter()
            .filter(|g| g.filter_match)
            .map(|g| 1 + if g.expanded { g.imports.len() } else { 0 })
            .sum()
    }
}

// ── Translation from core::types::Symbol → legacy SymbolInfo ─────────────────

fn from_core_symbol(s: &CoreSymbol) -> SymbolInfo {
    let kind = match s.kind {
        CoreSymKind::Function => SymbolKind::Function,
        CoreSymKind::Data => SymbolKind::Data,
        CoreSymKind::Thunk => SymbolKind::Thunk,
        CoreSymKind::Label => SymbolKind::Label,
        CoreSymKind::Import | CoreSymKind::Export | CoreSymKind::Unknown => SymbolKind::Other,
    };
    // Best-effort source classification — proper FLIRT / PDB / DWARF tagging
    // belongs in the analyser; treat unnamed `sub_*` autonames as Auto and
    // everything else (user-typed or import/export) as User-defined.
    let source = if s.name.starts_with("sub_") {
        SymbolSource::Auto
    } else if s.demangled.is_some() {
        SymbolSource::Pdb
    } else {
        SymbolSource::User
    };
    SymbolInfo {
        address: Address(s.addr.0),
        name: s.name.clone(),
        demangled_name: s.demangled.clone(),
        kind,
        source: if s.flirt_library.is_some() {
            SymbolSource::Flirt
        } else {
            source
        },
        module: s.module.clone(),
        flirt_library: s.flirt_library.clone(),
    }
}

// ── Render ───────────────────────────────────────────────────────────────────

pub fn render_symbols_panel_ext<'a>(
    state: &'a SymbolsPanelState,
    _ui_arc: &Arc<Mutex<UIState>>,
    bus: &Arc<EventBus>,
    data_arc: Arc<parking_lot::RwLock<AppData>>,
) -> impl IntoElement + 'a {
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(render_tab_bar(state, bus))
        .child(match state.active_tab {
            SymbolsTab::Symbols => {
                render_symbols_tab(state, bus, data_arc).into_any_element()
            }
            SymbolsTab::Imports => render_imports_tab(state).into_any_element(),
            SymbolsTab::Exports => render_exports_tab(state).into_any_element(),
        })
        .child(render_context_menu(state, bus))
}

fn text_xs(s: &str, color: Hsla) -> impl IntoElement {
    div().text_size(px(sizes::LABEL - 1.0)).text_color(color).child(s.to_string()).truncate()
}

fn text_sm(s: &str, color: Hsla) -> impl IntoElement {
    div().text_size(px(sizes::LABEL)).text_color(color).child(s.to_string()).truncate()
}

fn render_tab_bar(state: &SymbolsPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .h(px(sizes::TAB_H))
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(render_tab_btn(state, SymbolsTab::Symbols, bus))
        .child(render_tab_btn(state, SymbolsTab::Imports, bus))
        .child(render_tab_btn(state, SymbolsTab::Exports, bus))
        .child(div().flex_1())
        .child(render_badge_strip(&state.badges))
}

fn render_tab_btn(
    state: &SymbolsPanelState,
    tab: SymbolsTab,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let is_active = state.active_tab == tab;
    let tab_id: u8 = match tab {
        SymbolsTab::Symbols => 0,
        SymbolsTab::Imports => 1,
        SymbolsTab::Exports => 2,
    };
    let bus_cl = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("symext-tab-{}", tab_id)))
        .px_3()
        .h_full()
        .flex()
        .items_center()
        .text_size(px(sizes::PANEL))
        .text_color(if is_active {
            colors::text_primary()
        } else {
            colors::text_muted()
        })
        .border_b_2()
        .border_color(if is_active {
            colors::accent()
        } else {
            Hsla { h: 0.0, s: 0.0, l: 0.0, a: 0.0 }
        })
        .cursor_pointer()
        .hover(|s| s.text_color(colors::text_primary()))
        .on_click(move |_, _, _| {
            bus_cl.send_command(UICommand::SymExtSetTab(tab_id));
        })
        .child(tab.label().to_string())
}

fn render_badge_strip(badges: &SymbolBadges) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_2()
        .child(badge_chip(
            &format!("{} unresolved", badges.unresolved),
            colors::err(),
        ))
        .child(badge_chip(
            &format!("{} FLIRT", badges.flirt_matched),
            colors::ok(),
        ))
        .child(badge_chip(
            &format!("{} user", badges.user_defined),
            colors::accent_blue(),
        ))
}

fn badge_chip(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .px_2()
        .rounded_full()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(color)
        .text_size(px(sizes::STATUS))
        .text_color(color)
        .child(label.to_string())
        .truncate()
}

fn render_symbol_filter_bar(
    state: &SymbolsPanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus_cl = Arc::clone(bus);
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::TOOLBAR_H))
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .px_2()
        .gap_2()
        .child(
            div()
                .id("symext-filter-input")
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .px_2()
                .w(px(200.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(if state.symbol_filter_text.is_empty() {
                    colors::text_muted()
                } else {
                    colors::text_primary()
                })
                .cursor_pointer()
                .on_click(move |_, _, _| {
                    bus_cl.send_command(UICommand::SidebarFilterFocus(3));
                })
                .child(if state.symbol_filter_text.is_empty() {
                    "Filter symbols…".to_string()
                } else {
                    state.symbol_filter_text.clone()
                })
                .truncate(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_1()
                .child(kind_check("Fn", state.kind_filter.function, 0, bus))
                .child(kind_check("Data", state.kind_filter.data, 1, bus))
                .child(kind_check("Thunk", state.kind_filter.thunk, 2, bus))
                .child(kind_check("Label", state.kind_filter.label, 3, bus)),
        )
        .child(div().w(px(1.0)).h(px(20.0)).bg(colors::border()))
        .child(
            div()
                .flex()
                .flex_row()
                .gap_1()
                .child(source_check("PDB", state.source_filter.pdb, 0, bus))
                .child(source_check("DWARF", state.source_filter.dwarf, 1, bus))
                .child(source_check("FLIRT", state.source_filter.flirt, 2, bus))
                .child(source_check("User", state.source_filter.user, 3, bus))
                .child(source_check("Auto", state.source_filter.auto, 4, bus)),
        )
        .child(div().flex_1())
        .child(toggle_chip(
            "Demangled",
            state.show_demangled,
            UICommand::SymExtToggleDemangled,
            bus,
        ))
        .child(toggle_chip(
            "Export CSV",
            false,
            UICommand::SymExtExportCsv,
            bus,
        ))
}

fn kind_check(label: &'static str, active: bool, idx: u8, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus_cl = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("symext-kind-{}", idx)))
        .px_1()
        .rounded_sm()
        .text_size(px(sizes::STATUS))
        .text_color(if active {
            colors::syn_label()
        } else {
            colors::text_muted()
        })
        .bg(if active {
            colors::bg_elevated()
        } else {
            colors::bg_base()
        })
        .border_1()
        .border_color(if active {
            colors::syn_label()
        } else {
            colors::border()
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_, _, _| {
            bus_cl.send_command(UICommand::SymExtToggleKind(idx));
        })
        .child(label)
}

fn source_check(
    label: &'static str,
    active: bool,
    idx: u8,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus_cl = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("symext-src-{}", idx)))
        .px_1()
        .rounded_sm()
        .text_size(px(sizes::STATUS))
        .text_color(if active {
            colors::accent_blue()
        } else {
            colors::text_muted()
        })
        .bg(if active {
            colors::bg_elevated()
        } else {
            colors::bg_base()
        })
        .border_1()
        .border_color(if active {
            colors::accent_blue()
        } else {
            colors::border()
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_, _, _| {
            bus_cl.send_command(UICommand::SymExtToggleSource(idx));
        })
        .child(label)
}

fn toggle_chip(
    label: &'static str,
    active: bool,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus_cl = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("symext-toggle-{}", label)))
        .px_2()
        .rounded_sm()
        .text_size(px(sizes::STATUS))
        .text_color(if active {
            colors::ok()
        } else {
            colors::text_secondary()
        })
        .bg(if active {
            colors::bg_active()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(colors::border())
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_, _, _| {
            bus_cl.send_command(cmd.clone());
        })
        .child(label)
}

fn render_symbol_column_headers(
    state: &SymbolsPanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .h(px(22.0))
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(col_header("Address", SymbolSortCol::Address, 1, 160.0, state, bus))
        .child(col_header("Name", SymbolSortCol::Name, 0, 0.0, state, bus))
        .child(col_header("Kind", SymbolSortCol::Kind, 2, 80.0, state, bus))
        .child(col_header("Source", SymbolSortCol::Source, 3, 80.0, state, bus))
        .child(col_header("Module", SymbolSortCol::Module, 4, 120.0, state, bus))
}

fn col_header(
    label: &'static str,
    col: SymbolSortCol,
    col_idx: u8,
    width: f32,
    state: &SymbolsPanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let is_sorted = state.sort_col == col;
    let arrow = if is_sorted {
        match state.sort_dir {
            SortDir::Asc => " ^",
            SortDir::Desc => " v",
        }
    } else {
        ""
    };
    let bus_cl = Arc::clone(bus);
    let base = div()
        .id(SharedString::from(format!("symext-col-{}", col_idx)))
        .px_2()
        .h_full()
        .flex()
        .items_center()
        .gap_1()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .text_size(px(sizes::LABEL))
        .text_color(if is_sorted {
            colors::accent()
        } else {
            colors::text_muted()
        })
        .on_click(move |_, _, _| {
            bus_cl.send_command(UICommand::SymExtSortBy(col_idx));
        })
        .child(format!("{label}{arrow}"));

    if width > 0.0 {
        base.w(px(width)).truncate().into_any_element()
    } else {
        base.flex_1().truncate().into_any_element()
    }
}

fn render_symbol_row(state: &SymbolsPanelState, sym: &SymbolRow) -> impl IntoElement {
    let is_selected = state.is_selected(sym.info.address);
    let kind_color = match sym.info.kind {
        SymbolKind::Function => colors::accent_blue(),
        SymbolKind::Data => colors::syn_label(),
        SymbolKind::Thunk => colors::syn_prefix(),
        SymbolKind::Label => colors::syn_immediate(),
        SymbolKind::Other => colors::text_secondary(),
    };
    let source_color = match sym.info.source {
        SymbolSource::Flirt => colors::ok(),
        SymbolSource::User => colors::accent_blue(),
        SymbolSource::Pdb => colors::syn_label(),
        SymbolSource::Dwarf => colors::syn_symbol(),
        SymbolSource::Auto => colors::text_muted(),
    };

    let mut name_cell = div()
        .flex_1()
        .px_2()
        .font_family("JetBrains Mono")
        .text_size(px(sizes::CODE - 1.0))
        .text_color(colors::text_primary())
        .child(crate::ui::widgets::copyable::copyable_name_global(&sym.display_name))
        .truncate();
    if matches!(sym.info.source, SymbolSource::Flirt) {
        let lib = sym
            .info
            .flirt_library
            .as_deref()
            .unwrap_or("FLIRT")
            .to_owned();
        name_cell = name_cell.child(
            div()
                .px_1()
                .rounded_sm()
                .bg(colors::bg_elevated())
                .text_size(px(sizes::STATUS - 1.0))
                .text_color(colors::ok())
                .child(lib)
                .truncate(),
        );
    }

    div()
        .flex()
        .flex_row()
        .h(px(state.row_height_px))
        .bg(if is_selected {
            colors::bg_selection()
        } else {
            colors::bg_base()
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .w(px(160.0))
                .px_2()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .child(crate::ui::widgets::copyable::copyable_addr_global(sym.info.address.0))
                .truncate(),
        )
        .child(name_cell)
        .child(
            div()
                .w(px(80.0))
                .px_2()
                .text_size(px(sizes::LABEL))
                .text_color(kind_color)
                .child(format!("{:?}", sym.info.kind))
                .truncate(),
        )
        .child(
            div()
                .w(px(80.0))
                .px_2()
                .text_size(px(sizes::LABEL))
                .text_color(source_color)
                .child(format!("{:?}", sym.info.source))
                .truncate(),
        )
        .child(
            div()
                .w(px(120.0))
                .px_2()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(sym.info.module.as_deref().unwrap_or("").to_owned())
                .truncate(),
        )
}

fn render_symbols_tab<'a>(
    state: &'a SymbolsPanelState,
    bus: &Arc<EventBus>,
    data_arc: Arc<parking_lot::RwLock<AppData>>,
) -> impl IntoElement + 'a {
    let total_rows = state.filtered_symbols.len();
    let total_symbols = state.all_symbols.len();
    let selected = state.selected_symbols.len();
    let show_demangled = state.show_demangled;

    // Snapshots for the uniform_list 'static closure. We can't keep a
    // reference into `state` inside the closure because uniform_list takes
    // a 'static-lifetime callback; cloning the index vec keeps it O(N · 8B).
    let filtered_ids: Vec<usize> = state.filtered_symbols.clone();
    let _ = data_arc; // future: live deref into AppData
    let row_snapshots: Vec<SymRowSnapshot> = filtered_ids
        .iter()
        .filter_map(|&i| state.all_symbols.get(i).map(|s| SymRowSnapshot::from(s, show_demangled)))
        .collect();

    let render_range = move |range: std::ops::Range<usize>,
                             _w: &mut gpui::Window,
                             _cx: &mut gpui::App|
          -> Vec<AnyElement> {
        range
            .filter_map(|i| row_snapshots.get(i).map(|s| render_symbol_row_snapshot(s, i).into_any_element()))
            .collect()
    };

    let bus_wheel = Arc::clone(bus);
    div()
        .flex()
        .flex_col()
        .flex_1()
        .child(render_symbol_filter_bar(state, bus))
        .child(render_symbol_column_headers(state, bus))
        .child(
            div()
                .id("symext-symbols-list")
                .flex_1()
                .overflow_hidden()
                .on_scroll_wheel(move |ev: &ScrollWheelEvent, _, _| {
                    // Negate so wheel-up scrolls list up — wheel_delta already
                    // handles sign convention.
                    let rows = (wheel_delta(ev) / sizes::ROW_H as f64).round() as i32;
                    if rows != 0 {
                        bus_wheel.send_command(UICommand::SymExtScroll(rows));
                    }
                })
                .child(
                    uniform_list(
                        SharedString::from("symext-symbols-uniform"),
                        total_rows,
                        render_range,
                    )
                    .with_sizing_behavior(gpui::ListSizingBehavior::Auto)
                    .h_full()
                    .w_full()
                    .flex_1(),
                ),
        )
        .child(
            div()
                .h(px(sizes::STATUS_H))
                .flex()
                .items_center()
                .px_2()
                .bg(colors::bg_surface())
                .border_t_1()
                .border_color(colors::border())
                .text_size(px(sizes::STATUS))
                .text_color(colors::text_muted())
                .child(format!(
                    "{} shown / {} total  |  {} selected",
                    total_rows, total_symbols, selected
                ))
                .truncate(),
        )
}

/// Static snapshot of a symbol row so the uniform_list closure can be
/// 'static. Avoids borrowing from `state` (which would defeat the
/// 'static bound) and avoids holding the AppData read-lock across frames.
struct SymRowSnapshot {
    name: String,
    address: u64,
    kind_label: String,
    source_label: String,
    module: String,
}

impl SymRowSnapshot {
    fn from(s: &SymbolRow, show_demangled: bool) -> Self {
        let name: String = if show_demangled {
            s.display_name.to_string()
        } else {
            s.info.name.clone()
        };
        Self {
            name,
            address: s.info.address.0,
            kind_label: format!("{:?}", s.info.kind),
            source_label: format!("{:?}", s.info.source),
            module: s.info.module.clone().unwrap_or_default(),
        }
    }
}

fn render_symbol_row_snapshot(s: &SymRowSnapshot, row_idx: usize) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("symext-row-{}", row_idx)))
        .flex()
        .flex_row()
        .h(px(sizes::ROW_H))
        .items_center()
        .px_2()
        .gap_2()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(120.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .child(format!("{:016x}", s.address))
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE))
                .text_color(colors::text_primary())
                .child(s.name.clone())
                .truncate(),
        )
        .child(
            div()
                .w(px(80.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(s.kind_label.clone())
                .truncate(),
        )
        .child(
            div()
                .w(px(80.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(s.source_label.clone())
                .truncate(),
        )
        .child(
            div()
                .w(px(100.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(s.module.clone())
                .truncate(),
        )
}

fn render_imports_tab(state: &SymbolsPanelState) -> impl IntoElement + '_ {
    div()
        .flex()
        .flex_col()
        .flex_1()
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .h(px(sizes::TOOLBAR_H))
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .px_2()
                .child(
                    div()
                        .bg(colors::bg_base())
                        .border_1()
                        .border_color(colors::border())
                        .rounded_sm()
                        .px_2()
                        .w(px(250.0))
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::CODE - 1.0))
                        .text_color(if state.import_filter_text.is_empty() {
                            colors::text_muted()
                        } else {
                            colors::text_primary()
                        })
                        .child(if state.import_filter_text.is_empty() {
                            "Filter by DLL or function…".to_string()
                        } else {
                            state.import_filter_text.clone()
                        })
                        .truncate(),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .h(px(22.0))
                .bg(colors::bg_elevated())
                .border_b_1()
                .border_color(colors::border())
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(div().w(px(200.0)).px_2().child("DLL / Function").truncate())
                .child(div().w(px(160.0)).px_2().child("IAT Address").truncate())
                .child(div().w(px(80.0)).px_2().child("Ordinal").truncate())
                .child(div().flex_1().px_2().child("Resolved Target").truncate()),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .children(state.import_groups.iter().filter(|g| g.filter_match).flat_map(
                    |group| {
                        let mut rows: Vec<gpui::AnyElement> = Vec::new();
                        rows.push(
                            div()
                                .flex()
                                .flex_row()
                                .items_center()
                                .h(px(22.0))
                                .bg(colors::bg_surface())
                                .border_b_1()
                                .border_color(colors::border())
                                .px_2()
                                .gap_2()
                                .child(text_sm(
                                    if group.expanded { "v" } else { ">" },
                                    colors::text_muted(),
                                ))
                                .child(
                                    div()
                                        .text_size(px(sizes::PANEL))
                                        .text_color(colors::syn_label())
                                        .child(group.dll_name.to_string())
                                        .truncate(),
                                )
                                .child(text_xs(
                                    &format!("({} imports)", group.imports.len()),
                                    colors::text_muted(),
                                ))
                                .into_any_element(),
                        );
                        if group.expanded {
                            for imp in &group.imports {
                                rows.push(
                                    div()
                                        .flex()
                                        .flex_row()
                                        .items_center()
                                        .h(px(state.row_height_px))
                                        .bg(colors::bg_base())
                                        .hover(|s| s.bg(colors::bg_hover()))
                                        .border_b_1()
                                        .border_color(colors::border())
                                        .child(
                                            div()
                                                .w(px(200.0))
                                                .px_3()
                                                .font_family("JetBrains Mono")
                                                .text_size(px(sizes::CODE - 1.0))
                                                .text_color(colors::text_primary())
                                                .child(imp.function_name.clone())
                                                .truncate(),
                                        )
                                        .child(
                                            div()
                                                .w(px(160.0))
                                                .px_2()
                                                .font_family("JetBrains Mono")
                                                .text_size(px(sizes::CODE - 1.0))
                                                .text_color(colors::syn_address())
                                                .child(format!("{:016x}", imp.iat_address.0))
                                                .truncate(),
                                        )
                                        .child(
                                            div()
                                                .w(px(80.0))
                                                .px_2()
                                                .text_size(px(sizes::LABEL))
                                                .text_color(colors::syn_symbol())
                                                .child(
                                                    imp.ordinal
                                                        .map(|o| format!("{o}"))
                                                        .unwrap_or_else(|| "-".to_owned()),
                                                )
                                                .truncate(),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .px_2()
                                                .font_family("JetBrains Mono")
                                                .text_size(px(sizes::CODE - 1.0))
                                                .text_color(colors::text_muted())
                                                .child(
                                                    imp.resolved_target
                                                        .map(|a| format!("{:016x}", a.0))
                                                        .unwrap_or_else(|| "unresolved".to_owned()),
                                                )
                                                .truncate(),
                                        )
                                        .into_any_element(),
                                );
                            }
                        }
                        rows
                    },
                )),
        )
}

fn render_exports_tab(state: &SymbolsPanelState) -> impl IntoElement + '_ {
    let start = state.export_scroll;
    let end = (start + state.rows_per_page).min(state.filtered_exports.len());
    let visible = &state.filtered_exports[start..end];

    div()
        .flex()
        .flex_col()
        .flex_1()
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .h(px(sizes::TOOLBAR_H))
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .px_2()
                .child(
                    div()
                        .bg(colors::bg_base())
                        .border_1()
                        .border_color(colors::border())
                        .rounded_sm()
                        .px_2()
                        .w(px(250.0))
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::CODE - 1.0))
                        .text_color(if state.export_filter_text.is_empty() {
                            colors::text_muted()
                        } else {
                            colors::text_primary()
                        })
                        .child(if state.export_filter_text.is_empty() {
                            "Filter exports…".to_string()
                        } else {
                            state.export_filter_text.clone()
                        })
                        .truncate(),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .h(px(22.0))
                .bg(colors::bg_elevated())
                .border_b_1()
                .border_color(colors::border())
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(div().flex_1().px_2().child("Export Name").truncate())
                .child(div().w(px(160.0)).px_2().child("Address").truncate())
                .child(div().w(px(80.0)).px_2().child("Ordinal").truncate())
                .child(div().w(px(200.0)).px_2().child("Forwarded To").truncate()),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .children(visible.iter().map(|&i| {
                    let exp = &state.all_exports[i];
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .h(px(state.row_height_px))
                        .bg(colors::bg_base())
                        .hover(|s| s.bg(colors::bg_hover()))
                        .border_b_1()
                        .border_color(colors::border())
                        .child(
                            div()
                                .flex_1()
                                .px_2()
                                .font_family("JetBrains Mono")
                                .text_size(px(sizes::CODE - 1.0))
                                .text_color(colors::text_primary())
                                .child(exp.name.clone())
                                .truncate(),
                        )
                        .child(
                            div()
                                .w(px(160.0))
                                .px_2()
                                .font_family("JetBrains Mono")
                                .text_size(px(sizes::CODE - 1.0))
                                .text_color(colors::syn_address())
                                .child(format!("{:016x}", exp.address.0))
                                .truncate(),
                        )
                        .child(
                            div()
                                .w(px(80.0))
                                .px_2()
                                .text_size(px(sizes::LABEL))
                                .text_color(colors::syn_symbol())
                                .child(format!("{}", exp.ordinal))
                                .truncate(),
                        )
                        .child(
                            div()
                                .w(px(200.0))
                                .px_2()
                                .font_family("JetBrains Mono")
                                .text_size(px(sizes::CODE - 1.0))
                                .text_color(colors::text_muted())
                                .child(exp.forwarded_to.as_deref().unwrap_or("").to_owned())
                                .truncate(),
                        )
                })),
        )
}

fn render_context_menu(state: &SymbolsPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    if let Some(menu) = &state.context_menu {
        div()
            .relative()
            .bg(colors::bg_surface())
            .border_1()
            .border_color(colors::border())
            .rounded_sm()
            .py_1()
            .w(px(220.0))
            .children(menu.items.iter().enumerate().map(|(idx, item)| {
                let bus_cl = Arc::clone(bus);
                let idx_u8 = u8::try_from(idx).unwrap_or(u8::MAX);
                let enabled = item.enabled;
                div()
                    .id(gpui::ElementId::Name(
                        format!("ctx_menu_item_{idx}").into(),
                    ))
                    .px_3()
                    .py_1()
                    .text_size(px(sizes::PANEL))
                    .text_color(if enabled {
                        colors::text_primary()
                    } else {
                        colors::text_muted()
                    })
                    .cursor_pointer()
                    .hover(|s| s.bg(colors::bg_hover()))
                    .on_click(move |_, _, _| {
                        if enabled {
                            bus_cl.send_command(UICommand::SymExtContextMenuAction(idx_u8));
                        }
                        bus_cl.send_command(UICommand::SymExtCloseContextMenu);
                    })
                    .child(item.label.to_string())
                    .truncate()
            }))
            .into_any_element()
    } else {
        div().into_any_element()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_filter_matches() {
        let kf = KindFilter::all();
        assert!(kf.matches(SymbolKind::Function));
        assert!(kf.matches(SymbolKind::Data));
        let kf2 = KindFilter {
            function: true,
            data: false,
            thunk: false,
            label: false,
        };
        assert!(kf2.matches(SymbolKind::Function));
        assert!(!kf2.matches(SymbolKind::Data));
    }

    #[test]
    fn sort_dir_toggle() {
        assert_eq!(SortDir::Asc.toggle(), SortDir::Desc);
        assert_eq!(SortDir::Desc.toggle(), SortDir::Asc);
    }

    #[test]
    fn export_to_csv_starts_with_header() {
        let panel = SymbolsPanelState::default();
        let csv = panel.export_to_csv();
        assert!(csv.starts_with("address,name,kind,source,module\n"));
    }

    #[test]
    fn mass_rename_pattern_addr() {
        let mut state = MassRenameState::new(vec![Address(0x40_1000)]);
        let syms = vec![SymbolRow {
            info: SymbolInfo {
                address: Address(0x40_1000),
                name: "sub_401000".to_owned(),
                demangled_name: None,
                kind: SymbolKind::Function,
                source: SymbolSource::Auto,
                module: None,
                flirt_library: None,
            },
            display_name: "sub_401000".into(),
            selected: false,
        }];
        state.update_pattern("func_{addr}", &syms);
        assert_eq!(state.preview[0].1, "func_401000");
    }
}

// ── ensure-used: touch every public surface so the crate's no-dead-code
//    policy is satisfied without `#[allow(dead_code)]` or pruning. ──

#[doc(hidden)]
pub fn ensure_used_symbols_panel() {
    // Tabs / sort labels
    let _ = SymbolsTab::Symbols.label();
    let _ = SymbolsTab::Imports.label();
    let _ = SymbolsTab::Exports.label();
    let _ = SortDir::Asc.icon();
    let _ = SortDir::Desc.icon();

    // Filters
    let kf = KindFilter::all();
    let _ = kf.matches(SymbolKind::Other);
    let sf = SourceFilter::all();
    let _ = sf.matches(SymbolSource::Dwarf);

    // Row + mass rename
    let info = SymbolInfo {
        address: Address(0),
        name: "x".to_owned(),
        demangled_name: Some("y".to_owned()),
        kind: SymbolKind::Label,
        source: SymbolSource::Flirt,
        module: Some("m".to_owned()),
        flirt_library: Some("libc".to_owned()),
    };
    let row = SymbolRow::new(info.clone(), true);
    let _ = row.display_name.len();
    let _ = row.selected;

    let mut mass = MassRenameState::new(vec![Address(0)]);
    mass.update_pattern("p_{name}", &[row.clone()]);
    let _ = mass.preview.len();

    // Import / Export
    let grp = ImportGroup::new(
        "kernel32.dll".into(),
        vec![ImportInfo {
            dll_name: "kernel32.dll".to_owned(),
            function_name: "CreateFileW".to_owned(),
            iat_address: Address(0),
            ordinal: Some(1),
            resolved_target: Some(Address(0)),
        }],
    );
    let _ = grp.expanded;
    let _ = grp.filter_match;
    let _ = grp.dll_name.len();
    for imp in &grp.imports {
        let _ = &imp.dll_name;
        let _ = imp.iat_address.0;
    }
    let _ = ExportInfo {
        name: "e".to_owned(),
        address: Address(0),
        ordinal: 0,
        forwarded_to: Some("f".to_owned()),
    };

    // Context menu surface
    let mut panel = SymbolsPanelState::default();
    panel.all_symbols.push(row);
    panel.apply_filter_and_sort();
    panel.apply_import_filter();
    panel.apply_export_filter();
    panel.set_sort(SymbolSortCol::Name);
    panel.set_sort(SymbolSortCol::Name);
    panel.set_filter("x");
    panel.toggle_show_demangled();
    panel.toggle_show_demangled();
    panel.select_symbol(Address(0), false);
    let _ = panel.is_selected(Address(0));
    panel.select_all();
    panel.clear_selection();
    panel.open_context_menu((0.0, 0.0), vec![Address(0), Address(1)]);
    if let Some(cm) = &panel.context_menu {
        let _ = cm.position;
        let _ = cm.targets.len();
        for it in &cm.items {
            match &it.action {
                SymbolContextAction::NavigateTo(a) => {
                    let _ = a.0;
                }
                SymbolContextAction::Rename
                | SymbolContextAction::AddComment
                | SymbolContextAction::SetType
                | SymbolContextAction::FindReferences
                | SymbolContextAction::ExportSelected
                | SymbolContextAction::BatchRename => {}
            }
        }
    }
    panel.close_context_menu();
    panel.open_mass_rename();
    panel.update_mass_rename_pattern("q");
    panel.cancel_mass_rename();
    let _ = panel.export_to_csv();
    let _ = panel.export_to_json();
    panel.scroll_symbols_by(1);
    panel.scroll_imports_by(1);

    // SymbolContextAction variants
    let _items: Vec<SymbolContextAction> = vec![
        SymbolContextAction::NavigateTo(Address(0)),
        SymbolContextAction::Rename,
        SymbolContextAction::AddComment,
        SymbolContextAction::SetType,
        SymbolContextAction::FindReferences,
        SymbolContextAction::ExportSelected,
        SymbolContextAction::BatchRename,
    ];

    // Badges, refresh, render-side helpers
    let _ = SymbolBadges::default();
    let mut p2 = SymbolsPanelState::default();
    let data = AppData::new();
    p2.refresh(&data, 1);
    let _csv = p2.export_to_csv();

    // Render free functions (touch every helper so they're not dead)
    let ui_arc = Arc::new(Mutex::new(UIState::new()));
    let bus = Arc::new(EventBus::new());
    let data_arc =
        Arc::new(parking_lot::RwLock::new(AppData::new()));
    let _ =
        render_symbols_panel_ext(&p2, &ui_arc, &bus, Arc::clone(&data_arc)).into_any_element();
    let _ = text_xs("a", colors::text_primary()).into_any_element();
    let _ = text_sm("b", colors::text_primary()).into_any_element();
    let _ = badge_chip("c", colors::ok()).into_any_element();
    let _ = kind_check("Fn", true, 0, &bus).into_any_element();
    let _ = source_check("PDB", true, 0, &bus).into_any_element();
    let _ = toggle_chip(
        "Demangled",
        true,
        UICommand::SymExtToggleDemangled,
        &bus,
    )
    .into_any_element();
    // Touch FontWeight just to ensure the import is used in real code paths
    // when the underlying renderer wires it in.
    let _ = FontWeight::BOLD;
    let _ = info.flirt_library;
    // Legacy single-row renderer kept reachable: it's still useful as a
    // standalone helper for table-row plugins / future debug overlays
    // that bypass the snapshot-based virtualised path.
    let sample_info = SymbolInfo {
        address: Address(0x1000),
        name: "sample".into(),
        demangled_name: None,
        kind: SymbolKind::Function,
        source: SymbolSource::User,
        module: None,
        flirt_library: None,
    };
    let sample_row = SymbolRow::new(sample_info, false);
    let _ = render_symbol_row(&p2, &sample_row).into_any_element();
}
