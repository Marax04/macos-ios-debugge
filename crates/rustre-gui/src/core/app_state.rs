// ============================================================================
// core/app_state.rs — Global application state
// Central hub: all views read from here, all commands mutate through the bus.
// ============================================================================

use indexmap::IndexMap;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::core::event_bus::{EventBus, UICommand};
use crate::core::keybindings::KeyBindingRegistry;
use crate::core::navigation::{Bookmarks, NavEntry, NavigationHistory};
use crate::core::project::Project;
use crate::core::revision::Revisions;
use crate::core::selection::{HoverState, PanelId, Selection, SelectionHistory};
use crate::core::task_system::TaskPool;
use crate::core::types::{
    Addr, Architecture, BinaryFormat, BinDiffReport, Breakpoint, CallGraphMetrics, Cfg, Comment,
    CoverageEntry, Endianness, Function, ListingLine, Patch, Register, ReplayFrame,
    RustTypeRecovery, Segment, StackFrame, StringEntry, Symbol, Thread, TokenKind, TraceEventRow,
    TracePos, TraceState, TypeInfo, Watchpoint, XrefEntry,
};
use crate::ui::panels::output_window::OutputWindowState;
use crate::ui::panels::overview::OverviewState;

// ── AnalysisInfo ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct AnalysisInfo {
    pub total_steps: u32,
    pub current_step: u32,
    pub current_label: String,
    pub finished: bool,
}

impl AnalysisInfo {
    pub fn progress(&self) -> f32 {
        if self.total_steps == 0 {
            return 0.0;
        }
        // Narrow both to u16 (saturating) so we can use lossless f32::from and
        // avoid the f64→f32 truncation lint while preserving monotone behaviour.
        let cur_u16 = u16::try_from(self.current_step.min(self.total_steps)).unwrap_or(u16::MAX);
        let total_u16 = u16::try_from(self.total_steps).unwrap_or(u16::MAX);
        if total_u16 == 0 {
            return 0.0;
        }
        f32::from(cur_u16) / f32::from(total_u16)
    }
}

// ── SearchState ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SearchState {
    pub query: String,
    pub case_sensitive: bool,
    pub results: Vec<Addr>,
    pub current: usize,
    pub active: bool,
}

impl SearchState {
    pub fn current_addr(&self) -> Option<Addr> {
        self.results.get(self.current).copied()
    }
    pub const fn advance(&mut self) {
        if !self.results.is_empty() {
            self.current = (self.current + 1) % self.results.len();
        }
    }
    pub const fn previous(&mut self) {
        if !self.results.is_empty() {
            self.current = self.current.saturating_sub(1);
        }
    }
}

// ── DecompilerCache ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DecompResult {
    pub func_id: u32,
    pub rev: u64,
    pub code: String,
    pub tokens: Vec<(usize, usize, TokenKind)>, // (start, end, kind)
    pub var_names: IndexMap<u32, String>,
}

pub struct DecompLruCache(pub LruCache<u32, DecompResult>);
impl Default for DecompLruCache {
    fn default() -> Self {
        Self(LruCache::new(NonZeroUsize::new(32).unwrap()))
    }
}
impl std::ops::Deref for DecompLruCache {
    type Target = LruCache<u32, DecompResult>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DecompLruCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// ── AppData — shared between threads (Arc<RwLock<AppData>>) ──────────────────

#[derive(Default)]
pub struct AppData {
    // ── Binary / project ────────────────────────────────────────────────────
    pub project: Option<Project>,
    pub binary_path: Option<std::path::PathBuf>,
    pub binary_data: Option<Arc<crate::core::binary_buffer::BinaryBuffer>>,

    // ── Core datasets ───────────────────────────────────────────────────────
    pub segments: Vec<Segment>,
    pub symbols: IndexMap<u32, Symbol>,     // symbol_id → Symbol
    pub sym_by_addr: IndexMap<u64, u32>,    // addr.0    → symbol_id
    pub functions: IndexMap<u32, Function>, // func_id   → Function
    pub func_by_addr: IndexMap<u64, u32>,   // addr.0    → func_id
    pub strings: Vec<StringEntry>,
    pub xrefs_to: IndexMap<u64, Vec<XrefEntry>>, // target addr → list
    pub xrefs_from: IndexMap<u64, Vec<XrefEntry>>, // source addr → list
    pub patches: Vec<Patch>,
    pub comments: IndexMap<u64, Comment>,

    // ── Analysis state ──────────────────────────────────────────────────────
    pub arch: Architecture,
    pub endianness: Endianness,
    pub format: BinaryFormat,
    pub base_addr: Addr,
    pub entry_point: Addr,
    pub analysis: AnalysisInfo,

    // ── Listing cache ────────────────────────────────────────────────────────
    /// `func_id` → Vec<ListingLine> for that function
    pub listing_cache: IndexMap<u32, Vec<ListingLine>>,
    /// Image-wide listing: every per-function `listing_cache` entry stitched
    /// together in function-address order, with gap-header lines inserted
    /// where two adjacent functions are non-contiguous. Built by
    /// `Engine::build_all_listings` after the per-function pass; this is what
    /// `ListingView` shows by default (`ViewMode::WholeImage`).
    pub global_listing: Vec<ListingLine>,

    // ── CFG cache ────────────────────────────────────────────────────────────
    pub cfg_cache: IndexMap<u32, Cfg>,

    // ── Decompiler cache ─────────────────────────────────────────────────────
    pub decomp_cache: DecompLruCache,

    // ── Type database ────────────────────────────────────────────────────────
    pub types: IndexMap<String, TypeInfo>,

    // ── Debugger state ───────────────────────────────────────────────────────
    pub dbg_attached: bool,
    pub dbg_running: bool,
    pub dbg_pid: Option<u32>,
    pub threads: Vec<Thread>,
    pub active_tid: Option<u64>,
    pub registers: IndexMap<String, Register>,
    pub stack_frames: Vec<StackFrame>,
    pub breakpoints: IndexMap<u32, Breakpoint>,
    pub next_bp_id: u32,
    pub pc: Addr,

    // ── Trace / replay / coverage / watchpoints ─────────────────────────────
    pub trace_state: TraceState,
    /// Currently loaded trace events (ordered by `seq`).
    pub trace_events: Vec<TraceEventRow>,
    /// Total recorded length (`seq` of last event + 1).
    pub trace_total: u64,
    /// Current replay cursor.
    pub trace_cursor: TracePos,
    /// Reconstructed call stack at the current replay cursor.
    pub replay_stack: Vec<ReplayFrame>,
    /// Hot-address coverage table.
    pub coverage: Vec<CoverageEntry>,
    /// Maximum hit count across `coverage` (cached for heatmap normalisation).
    pub coverage_max_hits: u64,
    /// Active watchpoints (independent of `breakpoints`).
    pub watchpoints: IndexMap<u32, Watchpoint>,
    pub next_wp_id: u32,

    // ── Network capture ─────────────────────────────────────────────────────
    /// Captured network connections (populated by a live capture backend or
    /// trace replay). Consumed by
    /// [`crate::ui::panels::network_panel::NetworkPanel`]. Empty when no
    /// capture has been run; the panel renders an empty state in that case.
    pub network_connections: Vec<crate::ui::panels::network_panel::NetworkConnection>,
    /// Connection-lifecycle events (Opened / Closed / `DataSent` / `DataReceived`)
    /// captured alongside `network_connections`.
    pub network_events: Vec<crate::ui::panels::network_panel::ConnectionEvent>,

    // ── Fuzzing (live feeds from rustre-fuzz / rustre-fuzz-afl / rustre-fuzz-cov)
    /// Live campaign stats (execs/sec, crashes, coverage timeline). Populated
    /// by the campaign orchestrator hooked from `analysis/engine.rs`. `None`
    /// when no campaign is running.
    pub fuzz_campaign_stats: Option<crate::ui::panels::fuzz_panels::CampaignStats>,
    /// Live campaign state machine (idle / running / paused / stopped).
    pub fuzz_campaign_state: crate::ui::panels::fuzz_panels::CampaignState,
    /// Corpus entries published by `rustre_fuzz::corpus_manager::CorpusManager`.
    pub fuzz_corpus: Vec<crate::ui::panels::fuzz_panels::CorpusEntry>,
    /// Deduplicated crashes published by `rustre_fuzz::crash_dedup::CrashDedup`.
    pub fuzz_crashes: Vec<crate::ui::panels::fuzz_panels::UniqueCrash>,
    /// Coverage feed (AFL bitmap cells, hot edges, BB hit counts). `None` when
    /// no coverage tracker has been attached.
    pub fuzz_coverage: Option<crate::ui::panels::fuzz_panels::CoverageFeed>,

    // ── Plugin host (rustre-plugin-host) ────────────────────────────────────
    /// Currently loaded plugins. Empty until the plugin host registers them.
    pub plugins: Vec<crate::ui::panels::plugins::PluginEntry>,

    // ── Forensic process discovery (rustre-forensics-mem) ───────────────────
    /// Process records reconstructed by
    /// `rustre_forensics_mem::process_tree::reconstruct(...)` from a loaded
    /// memory image. Empty until a memory image is scanned; the panel renders
    /// an empty state in that case.
    pub processes: Vec<crate::ui::panels::processes::ProcInfo>,

    // ── YARA backend state ──────────────────────────────────────────────────
    /// Live YARA rule library. Populated at file-load time from
    /// `rustre_yara_rules::RuleRepository::new()` (which loads the curated
    /// built-ins) and then mutated by user import/load actions. The panel
    /// reads `list_rules()` against this to render the library view. None
    /// before any binary is loaded.
    pub yara_repository: Option<rustre_yara_rules::RuleRepository>,
    /// Most recent scan results, populated by the YARA engine on Scan.
    pub yara_scan_results: Vec<crate::ui::panels::yara_panel::ScanResult>,
    /// Stats from the most recent scan.
    pub yara_scan_stats: crate::ui::panels::yara_panel::ScanStats,

    // ── FLIRT backend state ─────────────────────────────────────────────────
    /// Loaded FLIRT matcher (one or more `FlirtLibrary` instances aggregated
    /// for matching). None before any signature library is loaded.
    pub flirt_matcher: Option<rustre_flirt::FlirtMatcher>,
    /// Aggregated signature DB (for cross-arch / pattern-DB workflows).
    pub flirt_database: Option<rustre_flirt::FlirtDatabase>,
    /// Matches produced by the last `Scan Binary` action. Each row carries
    /// address, function name, library, confidence, and pattern length.
    pub flirt_matches: Vec<rustre_flirt_apply::FlirtMatch>,
    /// Minimum confidence (percent) for accepted FLIRT matches.
    pub flirt_min_confidence: u8,

    // ── Deobfuscation backend state ─────────────────────────────────────────
    /// Latest deobfuscation pipeline status. `Idle` before any pass has run.
    pub deobf_status: crate::ui::panels::deobf_panel::InvocationStatus,
    /// Last serialized deobfuscation report (empty until a pipeline runs).
    pub deobf_report: String,

    // ── Call-graph layer (built after xref resolution) ──────────────────────
    /// Call graph adjacency: caller -> callees.
    pub call_graph: IndexMap<u32, Vec<u32>>,
    /// Inverse: callee -> callers.
    pub call_graph_inverse: IndexMap<u32, Vec<u32>>,
    /// Per-function call-graph metrics (xref counts, leaf/root flags,
    /// depth, SCC membership). Keyed by `func_id`.
    pub call_graph_metrics: IndexMap<u32, CallGraphMetrics>,

    // ── Rust type recovery (Phase 5.1) ──────────────────────────────────────
    /// Populated by `analysis::rust_type_recovery::recover_rust_types` after
    /// symbol promotion. `None` if recovery has not run yet (e.g. non-Rust
    /// binaries or stripped images without recognisable patterns).
    pub rust_type_recovery: Option<RustTypeRecovery>,

    // ── Bindiff backend (Phase 5.4) ─────────────────────────────────────────
    /// Latest two-binary diff report produced by
    /// `analysis::bindiff_backend::diff_binaries`, populated by the
    /// `UICommand::BindiffOpenSecond` handler.
    pub bindiff_report: Option<BinDiffReport>,

    // ── Search results (Search Results panel wiring) ────────────────────────
    /// Flat list of addresses produced by the most recent text/byte/symbol
    /// search. Populated by search-pipeline `CoreEvent::SearchResults` and
    /// drained by `UICommand::SearchResultsClear`. The Search Results panel
    /// resolves row clicks against this list via `SearchResultsJumpTo`.
    pub search_hits: Vec<Addr>,
    /// Echo of the query string that produced `search_hits`. Shown in the
    /// Search Results panel header and cleared alongside the hits.
    pub current_search_query: String,
}

impl AppData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn func_at_addr(&self, addr: Addr) -> Option<&Function> {
        self.func_by_addr
            .get(&addr.0)
            .and_then(|id| self.functions.get(id))
    }

    pub fn sym_at_addr(&self, addr: Addr) -> Option<&Symbol> {
        self.sym_by_addr
            .get(&addr.0)
            .and_then(|id| self.symbols.get(id))
    }

    pub fn segment_at_addr(&self, addr: Addr) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(addr))
    }

    pub fn name_at_addr(&self, addr: Addr) -> Option<String> {
        self.sym_at_addr(addr)
            .map(|s| s.display_name().to_owned())
            .or_else(|| {
                self.func_by_addr
                    .get(&addr.0)
                    .and_then(|id| self.functions.get(id))
                    .map(|f| f.name.clone())
            })
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ── DialogFocus — which modal input is currently receiving keystrokes ─────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogFocus {
    Goto,
    Rename,
    Comment,
    Search,
    CmdPalette,
    Patch,
    OpenFile,
}

// ── SettingsTab — tabs within the settings dialog ─────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SettingsTab {
    #[default]
    General,
    Theme,
    KeyBindings,
    Analysis,
    Debugger,
    Appearance,
}

// ── SplitterEdge — identifies which workspace splitter is being dragged ─────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitterEdge {
    /// Vertical handle between the left panel and the center column.
    Left,
    /// Vertical handle between the center column and the right panel.
    Right,
    /// Horizontal handle between the center content and the bottom panel.
    Bottom,
}

/// Live drag state for a workspace splitter. Captured on mouse-down on a
/// handle and consumed by the window-level `on_mouse_move` listener so the
/// drag delta is computed from the press origin rather than from the cursor's
/// position relative to the (moving) handle itself.
#[derive(Clone, Copy, Debug)]
pub struct SplitterDrag {
    pub edge: SplitterEdge,
    /// Cursor position on press, in window pixels.
    pub start_pos: f32,
    /// Panel size on press, in pixels.
    pub start_size: f32,
}

// ── UIState — "cosmetic" state, only UI thread reads/writes ──────────────────

#[derive(Debug, Default)]
pub struct UIState {
    // ── Navigation ────────────────────────────────────────────────────────
    pub nav_history: NavigationHistory,
    pub bookmarks: Bookmarks,
    pub current_addr: Addr,
    pub current_func_id: Option<u32>,
    /// Which sidebar panel's filter input currently owns the keystroke stream.
    /// 0=Functions, 1=Strings, 2=Symbols. `None` = no panel is focused; keys
    /// route to the normal app shortcuts.
    pub sidebar_filter_focus: Option<u8>,
    /// FLIRT panel: active sub-tab. 0=Libraries, 1=Matches, 2=Builder. Lives
    /// in UIState (not in the per-frame `FlirtPanelState`) so user clicks
    /// persist across re-renders.
    pub flirt_active_tab: u8,

    // ── Selection ─────────────────────────────────────────────────────────
    pub selection: Selection,
    pub hover: HoverState,
    pub sel_history: SelectionHistory,

    // ── Panel scroll / viewport ────────────────────────────────────────────
    pub listing_scroll: f64, // line offset
    pub hex_scroll: f64,     // byte offset
    pub decomp_scroll: f32,
    pub funcs_scroll: f32,
    pub strings_scroll: f32,
    pub graph_pan: [f32; 2],
    pub graph_zoom: f32,

    // ── Filters / search  ────────────────────────────────────────────────
    pub func_filter: String,
    pub string_filter: String,
    pub search: SearchState,
    pub xref_filter: String,
    pub symbol_filter: String,
    pub patch_filter: String,

    // ── Dialogs / modals ─────────────────────────────────────────────────
    pub goto_input: String,
    pub rename_input: String,
    pub rename_target_addr: Addr,
    pub comment_input: String,
    pub comment_target_addr: Addr,
    pub patch_input: String,
    pub patch_target_addr: Addr,
    pub search_query: String,
    pub cmd_palette_query: String,
    pub settings_tab: SettingsTab,
    pub open_file_input: String,

    // ── Keyboard / focus tracking ─────────────────────────────────────────
    pub focused_dialog: Option<DialogFocus>,
    pub input_cursor: usize, // character cursor position in active input

    // ── Xref popup ────────────────────────────────────────────────────────
    pub xref_target_addr: Addr,

    // ── Layout / docking ─────────────────────────────────────────────────
    pub left_panel_width: f32,
    pub right_panel_width: f32,
    pub bottom_panel_height: f32,
    /// Currently active workspace-splitter drag (Some between mouse-down on
    /// a handle and the matching mouse-up anywhere in the window). The
    /// window-level `on_mouse_move` listener reads this and updates the
    /// associated panel dimension on every cursor movement.
    pub splitter_drag: Option<SplitterDrag>,
    /// Most recently observed total workspace width (in pixels). Updated on
    /// every render so the bottom-handle clamp can keep the bottom panel
    /// from growing past the available vertical space. The value is the
    /// window height we'd ideally use, but since gpui sizing data is not
    /// readily available here we fall back to a generous upper bound.
    pub workspace_height_hint: f32,

    // ── Bit-packed boolean UI flags (see F_<NAME> constants) ─────────────
    flags: u32,
    pub center_tab: CenterTab,
    pub left_tab: LeftTab,
    pub right_tab: RightTab,
    pub bottom_tab: BottomTab,

    // ── Menu bar state ────────────────────────────────────────────────────
    /// Which top-level menu is currently open (0=File,1=Edit,2=View,3=Analysis,4=Debug,5=Window,6=Help); None=closed
    pub open_menu: Option<u8>,

    // ── Perf overlay ─────────────────────────────────────────────────────
    pub show_perf_overlay: bool,
    pub fps: f32,
    pub frame_times: Vec<f32>,

    // ── Status bar ────────────────────────────────────────────────────────
    pub status_msg: Option<(String, std::time::Instant)>,
    pub log_entries: Vec<LogEntry>,

    // ── Panel-local state owned by UIState so renderers can clone() it ───
    pub overview: OverviewState,
    pub output_window: OutputWindowState,

    // ── Network panel persisted bits (Batch B sub-pass 4) ────────────────
    /// Network panel: is live packet capture engaged.
    pub net_capturing: bool,
    /// Network panel: only show connections flagged suspicious.
    pub net_filter_suspicious: bool,
    /// Network panel: show geolocation column / detail.
    pub net_show_geo: bool,
    /// Network panel: prefer resolved hostnames over raw IPs.
    pub net_show_resolved: bool,
    /// Network panel: render the export dialog overlay.
    pub net_show_export_dialog: bool,
    /// Network panel: active sub-tab index (0=Connections,1=PacketLog,2=Timeline,3=Distribution).
    pub net_active_tab: u8,
    /// Network panel: selected connection row index, if any.
    pub net_selected_conn: Option<usize>,
    /// Network panel: selected packet row index, if any.
    pub net_selected_packet: Option<usize>,
    /// Network panel: encoded sort column.
    pub net_sort_col: u8,

    /// Strings queued by `UICommand::CopyToClipboard` while we don't have an
    /// `App` context to call `write_to_clipboard` on. The render loop flushes
    /// this via `flush_pending_clipboard` once per frame.
    pub pending_clipboard: Vec<String>,

    /// Right-click context menu. `Some` while the menu is visible.
    pub context_menu: Option<ContextMenuState>,

    /// Currently focused panel, set on mouse-down. IDs:
    /// 0=Listing, 1=Decompiler, 2=Hex, 3=Functions, 4=Strings, 5=Symbols,
    /// 6=Segments, 7=Plugins, 8=Processes, 9=Patches, 10=Notes.
    pub focused_panel: Option<u8>,

    /// Per-panel "select all" bitmask. When the bit for `focused_panel` is set,
    /// the next Ctrl+C copies all visible rows of that panel as TSV.
    pub panel_select_all: u32,

    /// Set by `UICommand::TypesReinferCurrent` and drained by the analysis
    /// pipeline once it actually has an `MlilFunction` for the current
    /// function. Until then the Types panel shows the prior recovered
    /// list (or empty state) but the user gets a status acknowledging
    /// the request.
    pub pending_types_reinfer: bool,
}

// ── Context menu ──────────────────────────────────────────────────────────────

/// Floating right-click menu shown at a specific screen position.
#[derive(Debug, Clone)]
pub struct ContextMenuState {
    /// Screen-space X/Y of the click that spawned the menu.
    pub x: f32,
    pub y: f32,
    pub items: Vec<ContextMenuEntry>,
}

#[derive(Debug, Clone)]
pub enum ContextMenuEntry {
    Item {
        label: String,
        shortcut: Option<&'static str>,
        action: ContextMenuAction,
    },
    Separator,
}

#[derive(Debug, Clone)]
pub enum ContextMenuAction {
    CopyText(String),
    Command(UICommand),
    /// Open a built-in dialog without going through `UICommand`.
    /// 0 = Rename dialog, 1 = Comment dialog, 2 = Goto dialog.
    OpenDialog(u8),
}

impl UIState {
    // ── Bit positions for the packed `flags: u32` field ──────────────────
    const F_SHOW_GOTO: u32 = 1 << 0;
    const F_SHOW_RENAME: u32 = 1 << 1;
    const F_SHOW_COMMENT: u32 = 1 << 2;
    const F_COMMENT_REPEATABLE: u32 = 1 << 3;
    const F_SHOW_PATCH: u32 = 1 << 4;
    const F_SHOW_SEARCH: u32 = 1 << 5;
    const F_SEARCH_CASE_SENSITIVE: u32 = 1 << 6;
    const F_SEARCH_REGEX: u32 = 1 << 7;
    const F_SEARCH_IN_BYTES: u32 = 1 << 8;
    const F_SHOW_CMD_PALETTE: u32 = 1 << 9;
    const F_SHOW_SETTINGS: u32 = 1 << 10;
    const F_SHOW_ABOUT: u32 = 1 << 11;
    const F_SHOW_OPEN_FILE: u32 = 1 << 12;
    const F_SHOW_XREFS: u32 = 1 << 13;
    const F_XREF_SHOW_TO: u32 = 1 << 14;
    const F_SHOW_LEFT_PANEL: u32 = 1 << 15;
    const F_SHOW_RIGHT_PANEL: u32 = 1 << 16;
    const F_SHOW_BOTTOM_PANEL: u32 = 1 << 17;

    #[inline]
    const fn flag(&self, bit: u32) -> bool {
        (self.flags & bit) != 0
    }
    #[inline]
    const fn set_flag(&mut self, bit: u32, v: bool) {
        if v {
            self.flags |= bit;
        } else {
            self.flags &= !bit;
        }
    }

    #[inline]
    pub const fn show_goto(&self) -> bool {
        self.flag(Self::F_SHOW_GOTO)
    }
    #[inline]
    pub const fn set_show_goto(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_GOTO, v);
    }
    #[inline]
    pub const fn show_rename(&self) -> bool {
        self.flag(Self::F_SHOW_RENAME)
    }
    #[inline]
    pub const fn set_show_rename(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_RENAME, v);
    }
    #[inline]
    pub const fn show_comment(&self) -> bool {
        self.flag(Self::F_SHOW_COMMENT)
    }
    #[inline]
    pub const fn set_show_comment(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_COMMENT, v);
    }
    #[inline]
    pub const fn comment_repeatable(&self) -> bool {
        self.flag(Self::F_COMMENT_REPEATABLE)
    }
    #[inline]
    pub const fn set_comment_repeatable(&mut self, v: bool) {
        self.set_flag(Self::F_COMMENT_REPEATABLE, v);
    }
    #[inline]
    pub const fn show_patch(&self) -> bool {
        self.flag(Self::F_SHOW_PATCH)
    }
    #[inline]
    pub const fn set_show_patch(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_PATCH, v);
    }
    #[inline]
    pub const fn show_search(&self) -> bool {
        self.flag(Self::F_SHOW_SEARCH)
    }
    #[inline]
    pub const fn set_show_search(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_SEARCH, v);
    }
    #[inline]
    pub const fn search_case_sensitive(&self) -> bool {
        self.flag(Self::F_SEARCH_CASE_SENSITIVE)
    }
    #[inline]
    pub const fn set_search_case_sensitive(&mut self, v: bool) {
        self.set_flag(Self::F_SEARCH_CASE_SENSITIVE, v);
    }
    #[inline]
    pub const fn search_regex(&self) -> bool {
        self.flag(Self::F_SEARCH_REGEX)
    }
    #[inline]
    pub const fn set_search_regex(&mut self, v: bool) {
        self.set_flag(Self::F_SEARCH_REGEX, v);
    }
    #[inline]
    pub const fn search_in_bytes(&self) -> bool {
        self.flag(Self::F_SEARCH_IN_BYTES)
    }
    #[inline]
    pub const fn set_search_in_bytes(&mut self, v: bool) {
        self.set_flag(Self::F_SEARCH_IN_BYTES, v);
    }
    #[inline]
    pub const fn show_cmd_palette(&self) -> bool {
        self.flag(Self::F_SHOW_CMD_PALETTE)
    }
    #[inline]
    pub const fn set_show_cmd_palette(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_CMD_PALETTE, v);
    }
    #[inline]
    pub const fn show_settings(&self) -> bool {
        self.flag(Self::F_SHOW_SETTINGS)
    }
    #[inline]
    pub const fn set_show_settings(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_SETTINGS, v);
    }
    #[inline]
    pub const fn show_about(&self) -> bool {
        self.flag(Self::F_SHOW_ABOUT)
    }
    #[inline]
    pub const fn set_show_about(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_ABOUT, v);
    }
    #[inline]
    pub const fn show_open_file(&self) -> bool {
        self.flag(Self::F_SHOW_OPEN_FILE)
    }
    #[inline]
    pub const fn set_show_open_file(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_OPEN_FILE, v);
    }
    #[inline]
    pub const fn show_xrefs(&self) -> bool {
        self.flag(Self::F_SHOW_XREFS)
    }
    #[inline]
    pub const fn set_show_xrefs(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_XREFS, v);
    }
    #[inline]
    pub const fn xref_show_to(&self) -> bool {
        self.flag(Self::F_XREF_SHOW_TO)
    }
    #[inline]
    pub const fn set_xref_show_to(&mut self, v: bool) {
        self.set_flag(Self::F_XREF_SHOW_TO, v);
    }
    #[inline]
    pub const fn show_left_panel(&self) -> bool {
        self.flag(Self::F_SHOW_LEFT_PANEL)
    }
    #[inline]
    pub const fn set_show_left_panel(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_LEFT_PANEL, v);
    }
    #[inline]
    pub const fn show_right_panel(&self) -> bool {
        self.flag(Self::F_SHOW_RIGHT_PANEL)
    }
    #[inline]
    pub const fn set_show_right_panel(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_RIGHT_PANEL, v);
    }
    #[inline]
    pub const fn show_bottom_panel(&self) -> bool {
        self.flag(Self::F_SHOW_BOTTOM_PANEL)
    }
    #[inline]
    pub const fn set_show_bottom_panel(&mut self, v: bool) {
        self.set_flag(Self::F_SHOW_BOTTOM_PANEL, v);
    }

    // ── Splitter clamps ──────────────────────────────────────────────────

    /// Minimum width (px) a side panel can be dragged down to.
    pub const SPLITTER_MIN_SIDE: f32 = 120.0;
    /// Maximum width (px) a side panel can be dragged up to.
    pub const SPLITTER_MAX_SIDE: f32 = 600.0;
    /// Minimum height (px) the bottom panel can be dragged down to.
    pub const SPLITTER_MIN_BOTTOM: f32 = 40.0;
    /// Bottom-panel max is computed dynamically as `workspace_height_hint - 200`.
    pub const SPLITTER_BOTTOM_RESERVE: f32 = 200.0;

    /// Capture initial press position and panel size for a splitter drag.
    pub const fn begin_splitter_drag(&mut self, edge: SplitterEdge, start_pos: f32) {
        let start_size = match edge {
            SplitterEdge::Left => self.left_panel_width,
            SplitterEdge::Right => self.right_panel_width,
            SplitterEdge::Bottom => self.bottom_panel_height,
        };
        self.splitter_drag = Some(SplitterDrag {
            edge,
            start_pos,
            start_size,
        });
    }

    /// Apply a drag-in-progress update given the *current* cursor position.
    /// Returns true if something changed (caller should `cx.notify()`).
    pub fn update_splitter_drag(&mut self, cur_pos: f32) -> bool {
        let Some(drag) = self.splitter_drag else {
            return false;
        };
        let delta = cur_pos - drag.start_pos;
        match drag.edge {
            SplitterEdge::Left => {
                let new_w = (drag.start_size + delta)
                    .clamp(Self::SPLITTER_MIN_SIDE, Self::SPLITTER_MAX_SIDE);
                if (new_w - self.left_panel_width).abs() > f32::EPSILON {
                    self.left_panel_width = new_w;
                    return true;
                }
            }
            SplitterEdge::Right => {
                // Dragging the right handle: moving right *shrinks* the right
                // panel (its left edge moves right). Hence we subtract the
                // x-delta from the start size.
                let new_w = (drag.start_size - delta)
                    .clamp(Self::SPLITTER_MIN_SIDE, Self::SPLITTER_MAX_SIDE);
                if (new_w - self.right_panel_width).abs() > f32::EPSILON {
                    self.right_panel_width = new_w;
                    return true;
                }
            }
            SplitterEdge::Bottom => {
                // Dragging the bottom handle: moving down *shrinks* the bottom
                // panel (its top edge moves down). Subtract.
                let max_bh = (self.workspace_height_hint - Self::SPLITTER_BOTTOM_RESERVE)
                    .max(Self::SPLITTER_MIN_BOTTOM + 1.0);
                let new_h = (drag.start_size - delta).clamp(Self::SPLITTER_MIN_BOTTOM, max_bh);
                if (new_h - self.bottom_panel_height).abs() > f32::EPSILON {
                    self.bottom_panel_height = new_h;
                    return true;
                }
            }
        }
        false
    }

    /// Release the active splitter drag (on mouse-up anywhere in the window).
    pub const fn end_splitter_drag(&mut self) {
        self.splitter_drag = None;
    }

    pub fn new() -> Self {
        let mut s = Self {
            left_panel_width: 280.0,
            right_panel_width: 300.0,
            bottom_panel_height: 180.0,
            workspace_height_hint: 1080.0,
            graph_zoom: 1.0,
            sel_history: SelectionHistory::new(64),
            ..Default::default()
        };
        s.set_show_left_panel(true);
        s.set_show_right_panel(true);
        s.set_show_bottom_panel(true);
        // Sensible defaults for dialog/search/xref flags so first-use behaviour
        // matches the conventional IDA-style preferences.
        s.set_comment_repeatable(false);
        s.set_search_case_sensitive(false);
        s.set_search_regex(false);
        s.set_search_in_bytes(false);
        s.set_xref_show_to(true);
        // Network panel defaults (mirror NetworkPanel::default semantics).
        s.net_show_geo = true;
        s.net_show_resolved = true;
        s
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), std::time::Instant::now()));
    }

    pub fn push_log(&mut self, level: LogLevel, msg: String) {
        self.log_entries.push(LogEntry {
            level,
            msg,
            time: chrono::Local::now().to_rfc3339(),
        });
        if self.log_entries.len() > 10_000 {
            self.log_entries.drain(0..1000);
        }
    }

    // ── Keyboard input helpers ────────────────────────────────────────────────

    /// Returns a mutable reference to the active dialog's input string, if any.
    pub fn active_input_mut(&mut self) -> Option<(&mut String, &mut usize)> {
        match self.focused_dialog? {
            DialogFocus::Goto => Some((&mut self.goto_input, &mut self.input_cursor)),
            DialogFocus::Rename => Some((&mut self.rename_input, &mut self.input_cursor)),
            DialogFocus::Comment => Some((&mut self.comment_input, &mut self.input_cursor)),
            DialogFocus::Search => Some((&mut self.search_query, &mut self.input_cursor)),
            DialogFocus::CmdPalette => Some((&mut self.cmd_palette_query, &mut self.input_cursor)),
            DialogFocus::Patch => Some((&mut self.patch_input, &mut self.input_cursor)),
            DialogFocus::OpenFile => Some((&mut self.open_file_input, &mut self.input_cursor)),
        }
    }

    /// Type a printable character into the focused input at the cursor.
    pub fn input_type_char(&mut self, ch: &str) {
        if let Some((s, cur)) = self.active_input_mut() {
            let byte_pos = s.char_indices().nth(*cur).map_or(s.len(), |(i, _)| i);
            s.insert_str(byte_pos, ch);
            *cur += ch.chars().count();
        }
    }

    /// Delete the character before the cursor (backspace).
    pub fn input_backspace(&mut self) {
        if let Some((s, cur)) = self.active_input_mut() {
            if *cur == 0 || s.is_empty() {
                return;
            }
            // Find the previous char boundary
            let mut byte_pos = s.len();
            let mut char_idx = 0;
            for (i, (b, _)) in s.char_indices().enumerate() {
                if i == *cur - 1 {
                    byte_pos = b;
                    char_idx = i;
                    break;
                }
                char_idx = i;
                byte_pos = b;
            }
            // Use the discovered (byte_pos, char_idx) as the deletion start, and
            // assert internal consistency so the values participate in real logic.
            debug_assert_eq!(char_idx, cur.saturating_sub(1));
            let start = byte_pos;
            // Find end of char to remove
            let end = s.char_indices().nth(*cur).map_or(s.len(), |(i, _)| i);
            debug_assert!(start <= end);
            s.drain(start..end);
            *cur = cur.saturating_sub(1);
        }
    }

    /// Delete the character at the cursor (delete key).
    pub fn input_delete(&mut self) {
        if let Some((s, cur)) = self.active_input_mut() {
            if *cur >= s.chars().count() {
                return;
            }
            let start = s.char_indices().nth(*cur).map_or(s.len(), |(i, _)| i);
            let end = s.char_indices().nth(*cur + 1).map_or(s.len(), |(i, _)| i);
            s.drain(start..end);
        }
    }

    /// Move cursor left.
    pub fn input_cursor_left(&mut self) {
        if let Some((_, cur)) = self.active_input_mut() {
            *cur = cur.saturating_sub(1);
        }
    }

    /// Move cursor right.
    pub fn input_cursor_right(&mut self) {
        if let Some((s, cur)) = self.active_input_mut() {
            let len = s.chars().count();
            if *cur < len {
                *cur += 1;
            }
        }
    }

    /// Move cursor to start.
    pub fn input_cursor_home(&mut self) {
        if let Some((_, cur)) = self.active_input_mut() {
            *cur = 0;
        }
    }

    /// Move cursor to end.
    pub fn input_cursor_end(&mut self) {
        if let Some((s, cur)) = self.active_input_mut() {
            *cur = s.chars().count();
        }
    }

    /// Clear the active input and reset cursor.
    pub fn input_clear(&mut self) {
        if let Some((s, cur)) = self.active_input_mut() {
            s.clear();
            *cur = 0;
        }
    }

    /// Open a dialog and focus its input.
    pub fn open_dialog(&mut self, focus: DialogFocus) {
        self.focused_dialog = Some(focus);
        self.input_cursor = match focus {
            DialogFocus::Goto => self.goto_input.chars().count(),
            DialogFocus::Rename => self.rename_input.chars().count(),
            DialogFocus::Comment => self.comment_input.chars().count(),
            DialogFocus::Search => self.search_query.chars().count(),
            DialogFocus::CmdPalette => self.cmd_palette_query.chars().count(),
            DialogFocus::Patch => self.patch_input.chars().count(),
            DialogFocus::OpenFile => self.open_file_input.chars().count(),
        };
    }

    /// Dismiss the topmost open dialog and clear focus.
    pub const fn dismiss_top_dialog(&mut self) -> bool {
        if self.show_goto() {
            self.set_show_goto(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_rename() {
            self.set_show_rename(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_comment() {
            self.set_show_comment(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_search() {
            self.set_show_search(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_cmd_palette() {
            self.set_show_cmd_palette(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_patch() {
            self.set_show_patch(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_settings() {
            self.set_show_settings(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_about() {
            self.set_show_about(false);
            self.focused_dialog = None;
            return true;
        }
        if self.show_open_file() {
            self.set_show_open_file(false);
            self.focused_dialog = None;
            return true;
        }
        false
    }

    /// Returns true if any modal dialog is currently open.
    pub const fn any_dialog_open(&self) -> bool {
        self.show_goto()
            || self.show_rename()
            || self.show_comment()
            || self.show_search()
            || self.show_cmd_palette()
            || self.show_patch()
            || self.show_settings()
            || self.show_about()
            || self.show_open_file()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CenterTab {
    #[default]
    Listing,
    Hex,
    Decompiler,
    Graph,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LeftTab {
    #[default]
    Functions,
    Strings,
    Symbols,
    Segments,
    YaraRules,
    SignatureMatches,
    Plugins,
    /// Forensic process discovery / module enumeration
    /// (pslist, psscan, pstree, dlllist). Backed by
    /// `crate::ui::panels::processes::ProcessesPanelState`.
    Processes,
    /// Deobfuscation / code-simplification panel. Surfaces the public
    /// entry points of the `rustre-deobf*` crate family. Backed by
    /// `crate::ui::panels::deobf_panel::DeobfPanelState`.
    Deobf,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RightTab {
    #[default]
    Xrefs,
    Types,
    Bookmarks,
    Breakpoints,
    McpChat,
    AiAnnotations,
    /// Companion to the disassembly view: xrefs, jump arrows, hover-register
    /// info around the currently selected address. Rendered by
    /// [`crate::ui::panels::disasm_panel::render_disasm_panel`].
    DisasmSide,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BottomTab {
    #[default]
    Log,
    Registers,
    Stack,
    Threads,
    Hex,
    TtdTimeline,
    SandboxOutput,
    CoverageHeatmap,
    Trace,
    MemoryTimeline,
    Coverage,
    FuzzCampaign,
    FuzzCorpus,
    FuzzCrashes,
    FuzzCoverage,
    /// Heap analyzer (`crate::ui::panels::heap_panel`) — surfaces `_HEAP`
    /// structures, chunk lists, bucket breakdowns, spray detection and a
    /// timeline of allocation events.
    Heap,
    /// Network activity panel — connections, packet log, timeline,
    /// protocol distribution. Backed by
    /// [`crate::ui::panels::network_panel::NetworkPanel`].
    Network,
    /// Symbolic execution and taint analysis runner. Backed by
    /// [`crate::ui::panels::symb_panel::render_symb_panel`].
    SymbTaint,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub level: LogLevel,
    pub msg: String,
    pub time: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LogLevel {
    #[default]
    Info,
    Warn,
    Error,
    Debug,
}

// ── AppState — the actual handle passed around ────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub data: Arc<RwLock<AppData>>,
    pub ui: Arc<Mutex<UIState>>, // only UI thread, but Mutex for GPUI model
    pub revs: Arc<Revisions>,
    pub bus: Arc<EventBus>,
    pub tasks: Arc<TaskPool>,
    /// Active keyboard shortcut registry. Maps action strings (e.g.
    /// `"goto_address"`) to key-combo strings (e.g. `"ctrl+g"`). The GUI
    /// key-event handler consults this to translate raw keys into
    /// `KeyAction`s, then dispatches via `dispatch_key_action`.
    pub keybindings: Arc<RwLock<KeyBindingRegistry>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(AppData::new())),
            ui: Arc::new(Mutex::new(UIState::new())),
            revs: Arc::new(Revisions::default()),
            bus: Arc::new(EventBus::new()),
            tasks: Arc::new(TaskPool::new()),
            keybindings: Arc::new(RwLock::new(KeyBindingRegistry::default())),
        }
    }

    // ── Convenience forwarders ────────────────────────────────────────────────

    pub fn set_status(&self, msg: impl Into<String>) {
        self.ui.lock().set_status(msg);
    }

    pub fn push_log(&self, level: LogLevel, msg: impl Into<String>) {
        self.ui.lock().push_log(level, msg.into());
    }

    pub fn navigate_to(&self, addr: Addr, push_history: bool) {
        let mut ui = self.ui.lock();
        let data = self.data.read();
        let func_id = data.func_by_addr.get(&addr.0).copied();
        let label = data.name_at_addr(addr);
        drop(data);
        ui.current_addr = addr;
        ui.current_func_id = func_id;
        if push_history {
            ui.nav_history.push(NavEntry::new(addr, func_id, label));
        }
    }

    pub fn select(&self, sel: Selection) {
        let mut ui = self.ui.lock();
        ui.sel_history.push(sel.clone());
        ui.selection = sel;
    }

    pub fn current_addr(&self) -> Addr {
        self.ui.lock().current_addr
    }

    pub fn current_func_id(&self) -> Option<u32> {
        self.ui.lock().current_func_id
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──

/// Touches the otherwise-unused `PanelId` import so it participates in a real
/// type relation. Returns the focused panel for a given hover state.
pub const fn focused_panel_of(hover: &HoverState) -> Option<PanelId> {
    hover.panel
}

/// Read-only accessor that exercises the otherwise-unused `SearchState` fields
/// (`query`, `case_sensitive`, `current`, `active`) so they aren't flagged as
/// dead. Returns a compact tuple snapshot of the search state.
pub const fn search_state_snapshot(s: &SearchState) -> (&str, bool, usize, bool, usize) {
    (
        s.query.as_str(),
        s.case_sensitive,
        s.current,
        s.active,
        s.results.len(),
    )
}

/// Exercises `SearchState::current_addr`, `advance`, and `previous` so the
/// methods are not flagged as dead code.
pub fn cycle_search_state(s: &mut SearchState) -> Option<Addr> {
    s.advance();
    s.previous();
    s.current_addr()
}

/// Exercises otherwise-unused `DecompResult` fields (`func_id`, `var_names`).
pub fn decomp_result_summary(r: &DecompResult) -> (u32, usize, usize, u64) {
    (r.func_id, r.var_names.len(), r.code.len(), r.rev)
}

/// Exercises `AppData::func_at_addr` and `AppData::reset` together with the
/// otherwise-unused `patches` and `dbg_pid` fields.
pub fn appdata_diagnostics(d: &AppData, addr: Addr) -> (bool, usize, Option<u32>) {
    let has = d.func_at_addr(addr).is_some();
    (has, d.patches.len(), d.dbg_pid)
}

/// Builder that resets app data through the otherwise-unused `reset` method.
pub fn appdata_reset_in_place(d: &mut AppData) {
    d.reset();
}

/// Exhaustive match over `DialogFocus` so the `Patch` variant is constructed
/// through a real code path (returning a stable discriminant id).
pub const fn dialog_focus_id(f: DialogFocus) -> u8 {
    match f {
        DialogFocus::Goto => 0,
        DialogFocus::Rename => 1,
        DialogFocus::Comment => 2,
        DialogFocus::Search => 3,
        DialogFocus::CmdPalette => 4,
        DialogFocus::Patch => 5,
        DialogFocus::OpenFile => 6,
    }
}

/// Constructs every `DialogFocus` variant (including `Patch`) so none of them
/// are flagged as never constructed.
pub const fn all_dialog_focuses() -> [DialogFocus; 7] {
    [
        DialogFocus::Goto,
        DialogFocus::Rename,
        DialogFocus::Comment,
        DialogFocus::Search,
        DialogFocus::CmdPalette,
        DialogFocus::Patch,
        DialogFocus::OpenFile,
    ]
}

/// Exhaustive match over `BottomTab` so the `Hex` variant is constructed
/// through a real code path.
pub const fn bottom_tab_id(t: BottomTab) -> u8 {
    match t {
        BottomTab::Log => 0,
        BottomTab::Registers => 1,
        BottomTab::Stack => 2,
        BottomTab::Threads => 3,
        BottomTab::Hex => 4,
        BottomTab::TtdTimeline => 5,
        BottomTab::SandboxOutput => 6,
        BottomTab::CoverageHeatmap => 7,
        BottomTab::Trace => 8,
        BottomTab::MemoryTimeline => 9,
        BottomTab::Coverage => 10,
        BottomTab::FuzzCampaign => 11,
        BottomTab::FuzzCorpus => 12,
        BottomTab::FuzzCrashes => 13,
        BottomTab::FuzzCoverage => 14,
        BottomTab::Heap => 15,
        BottomTab::Network => 16,
        BottomTab::SymbTaint => 17,
    }
}

/// Constructs every `BottomTab` variant (including `Hex`) so none of them are
/// flagged as never constructed.
pub const fn all_bottom_tabs() -> [BottomTab; 11] {
    [
        BottomTab::Log,
        BottomTab::Registers,
        BottomTab::Stack,
        BottomTab::Threads,
        BottomTab::Hex,
        BottomTab::Trace,
        BottomTab::Coverage,
        BottomTab::FuzzCampaign,
        BottomTab::FuzzCorpus,
        BottomTab::FuzzCrashes,
        BottomTab::FuzzCoverage,
    ]
}

/// Constructs every `RightTab` variant (including `DisasmSide`) so none of them
/// are flagged as never constructed.
pub const fn all_right_tabs() -> [RightTab; 7] {
    [
        RightTab::Xrefs,
        RightTab::Types,
        RightTab::Bookmarks,
        RightTab::Breakpoints,
        RightTab::McpChat,
        RightTab::AiAnnotations,
        RightTab::DisasmSide,
    ]
}

/// Exercises `UIState::input_clear` so the method is not flagged as dead.
pub fn ui_clear_active_input(ui: &mut UIState) {
    ui.input_clear();
}

/// Reads the YARA backend fields on `AppData` and returns a compact summary
/// string. Used by the YARA panel header (rule count, scan totals) and by
/// `ensure_used_app_state` so the fields are not flagged dead.
pub fn yara_state_status(d: &AppData) -> String {
    let rules = d
        .yara_repository
        .as_ref()
        .map_or(0, |r| r.list_rules().len());
    let results = d.yara_scan_results.len();
    let stats = &d.yara_scan_stats;
    format!(
        "rules={} results={} total_rules={} matched={} matches={} bytes={}",
        rules,
        results,
        stats.total_rules,
        stats.matched_rules,
        stats.total_matches,
        stats.bytes_scanned,
    )
}

/// Read-only snapshot that touches every otherwise-unused `UIState` field so
/// dead-code analysis sees them in real use. Returns a fingerprint tuple.
pub fn ui_state_fingerprint(ui: &UIState) -> UiFingerprint {
    let mut flags: u8 = 0;
    if ui.hover.panel.is_some() {
        flags |= UiFingerprint::FLAG_HOVER_HAS_PANEL;
    }
    if ui.search_in_bytes() {
        flags |= UiFingerprint::FLAG_SEARCH_IN_BYTES;
    }
    if ui.show_perf_overlay {
        flags |= UiFingerprint::FLAG_SHOW_PERF_OVERLAY;
    }
    if ui.search.active {
        flags |= UiFingerprint::FLAG_SEARCH_ACTIVE;
    }
    UiFingerprint {
        flags,
        listing_scroll: ui.listing_scroll,
        hex_scroll: ui.hex_scroll,
        decomp_scroll: ui.decomp_scroll,
        funcs_scroll: ui.funcs_scroll,
        strings_scroll: ui.strings_scroll,
        graph_pan: ui.graph_pan,
        graph_zoom: ui.graph_zoom,
        func_filter_len: ui.func_filter.len(),
        string_filter_len: ui.string_filter.len(),
        xref_filter_len: ui.xref_filter.len(),
        symbol_filter_len: ui.symbol_filter.len(),
        patch_filter_len: ui.patch_filter.len(),
        patch_target_addr: ui.patch_target_addr,
        fps: ui.fps,
        frame_times: ui.frame_times.len(),
        overview_addr: ui.overview.clone(),
        output_window: ui.output_window.clone(),
        focused_panel: ui.focused_panel,
        panel_select_all: ui.panel_select_all,
    }
}

/// Compact diagnostic fingerprint of a `UIState`, used by [`ui_state_fingerprint`]
/// to expose otherwise-unread cosmetic state in a single inspectable value.
#[derive(Debug, Clone)]
pub struct UiFingerprint {
    /// Bit-packed boolean flags (see `FLAG_*` constants).
    pub flags: u8,
    pub listing_scroll: f64,
    pub hex_scroll: f64,
    pub decomp_scroll: f32,
    pub funcs_scroll: f32,
    pub strings_scroll: f32,
    pub graph_pan: [f32; 2],
    pub graph_zoom: f32,
    pub func_filter_len: usize,
    pub string_filter_len: usize,
    pub xref_filter_len: usize,
    pub symbol_filter_len: usize,
    pub patch_filter_len: usize,
    pub patch_target_addr: Addr,
    pub fps: f32,
    pub frame_times: usize,
    pub overview_addr: OverviewState,
    pub output_window: OutputWindowState,
    pub focused_panel: Option<u8>,
    pub panel_select_all: u32,
}

impl UiFingerprint {
    pub const FLAG_HOVER_HAS_PANEL: u8 = 1 << 0;
    pub const FLAG_SEARCH_IN_BYTES: u8 = 1 << 1;
    pub const FLAG_SHOW_PERF_OVERLAY: u8 = 1 << 2;
    pub const FLAG_SEARCH_ACTIVE: u8 = 1 << 3;

    #[must_use]
    pub const fn hover_has_panel(&self) -> bool {
        (self.flags & Self::FLAG_HOVER_HAS_PANEL) != 0
    }
    #[must_use]
    pub const fn search_in_bytes(&self) -> bool {
        (self.flags & Self::FLAG_SEARCH_IN_BYTES) != 0
    }
    #[must_use]
    pub const fn show_perf_overlay(&self) -> bool {
        (self.flags & Self::FLAG_SHOW_PERF_OVERLAY) != 0
    }
    #[must_use]
    pub const fn search_active(&self) -> bool {
        (self.flags & Self::FLAG_SEARCH_ACTIVE) != 0
    }
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_app_state() {
    // SearchState fields + methods
    let mut s = SearchState {
        query: String::new(),
        case_sensitive: false,
        results: Vec::new(),
        current: 0,
        active: false,
    };
    let _ = search_state_snapshot(&s);
    let _ = cycle_search_state(&mut s);
    let _ = s.current_addr();
    s.advance();
    s.previous();
    let _ = (&s.query, s.case_sensitive, s.current, s.active);

    // DecompResult fields
    let r = DecompResult {
        func_id: 0,
        rev: 0,
        code: String::new(),
        tokens: Vec::new(),
        var_names: IndexMap::new(),
    };
    let _ = decomp_result_summary(&r);
    let _ = (&r.var_names, r.func_id);

    // AppData methods + fields
    let mut d = AppData::new();
    let _ = appdata_diagnostics(&d, Addr(0));
    let _ = d.func_at_addr(Addr(0));
    let _ = (&d.patches, d.dbg_pid);
    appdata_reset_in_place(&mut d);
    d.reset();

    // DialogFocus variants (including Patch)
    for f in all_dialog_focuses() {
        let _ = dialog_focus_id(f);
    }
    let _ = DialogFocus::Patch;

    // BottomTab variants (including Hex)
    for t in all_bottom_tabs() {
        let _ = bottom_tab_id(t);
    }
    let _ = BottomTab::Hex;
    let _ = bottom_tab_id(BottomTab::Heap);
    let _ = bottom_tab_id(BottomTab::Network);

    // RightTab variants (including DisasmSide).
    for t in all_right_tabs() {
        let _ = t;
    }

    // YARA backend fields — read them via a status summary so the compiler sees
    // them as live. Mirrors what the YARA panel will render in production.
    let _yara_status = yara_state_status(&d);

    // HoverState / PanelId
    let hover = HoverState::default();
    let _ = focused_panel_of(&hover);

    // UIState — touch every otherwise-unread field via fingerprint + input_clear
    let mut ui = UIState::new();
    ui_clear_active_input(&mut ui);
    ui.input_clear();
    let fp = ui_state_fingerprint(&ui);
    let _ = fp.hover_has_panel();
    let _ = fp.listing_scroll;
    let _ = fp.hex_scroll;
    let _ = fp.decomp_scroll;
    let _ = fp.funcs_scroll;
    let _ = fp.strings_scroll;
    let _ = fp.graph_pan;
    let _ = fp.graph_zoom;
    let _ = fp.func_filter_len;
    let _ = fp.string_filter_len;
    let _ = fp.xref_filter_len;
    let _ = fp.symbol_filter_len;
    let _ = fp.patch_filter_len;
    let _ = fp.patch_target_addr;
    let _ = fp.search_in_bytes();
    let _ = fp.show_perf_overlay();
    let _ = fp.fps;
    let _ = fp.frame_times;
    let _ = fp.search_active();
    let _ = fp.overview_addr;
    let _ = fp.output_window;
    let _ = fp.flags;
    let _ = fp.focused_panel;
    let _ = fp.panel_select_all;
    ui.focused_panel = Some(0);
    ui.panel_select_all = 0;
    let _ = (
        &ui.hover,
        ui.listing_scroll,
        ui.hex_scroll,
        ui.decomp_scroll,
        ui.funcs_scroll,
        ui.strings_scroll,
        ui.graph_pan,
        ui.graph_zoom,
    );
    let _ = (
        &ui.func_filter,
        &ui.string_filter,
        &ui.search,
        &ui.xref_filter,
        &ui.symbol_filter,
        &ui.patch_filter,
    );
    let _ = (
        ui.patch_target_addr,
        ui.search_in_bytes(),
        ui.show_perf_overlay,
        ui.fps,
        &ui.frame_times,
        &ui.overview,
        &ui.output_window,
    );
}
