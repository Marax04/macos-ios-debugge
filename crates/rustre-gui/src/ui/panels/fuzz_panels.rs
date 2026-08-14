// ============================================================================
// ui/panels/fuzz_panels.rs — Zyphora panels for the fuzzing domain
//
// Five panels covering the GUI-side surface for the rustre-fuzz / rustre-fuzz-afl
// / rustre-fuzz-cov backend crates:
//
//   * FuzzCampaignPanel    — AFL++ campaign runner (start/stop/pause, seed
//                            corpus, executor selection, mutator config,
//                            fork-server settings) + real-time stats dashboard
//                            (execs/s, crashes, coverage timeline, corpus
//                            growth, queue size).
//   * CorpusViewerPanel    — Corpus browser & triage: list entries, filter by
//                            coverage bits, show parent/generation genealogy,
//                            serialize/export inputs.
//   * CrashAnalysisPanel   — Crash deduplicator/reporter: unique crashes grouped
//                            by stack hash + coverage, occurrence counts,
//                            exploitability estimates, stack-trace viewer.
//   * CoveragePanel        — Coverage heatmap, hot edges, run diff, basic-block
//                            hit counts, coverage density %.
//
// All five render through gpui in Zyphora's "Zyphora Dark" theme; data
// structures shadow the public surfaces of `rustre_fuzz::campaign`,
// `rustre_fuzz_afl::afl_corpus_manager` and `rustre_fuzz_cov::edge_coverage`
// so the backend can be wired in via setter methods without touching the
// render code.
// ============================================================================

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::{icon, icon_colored, icon_sized};
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};

// ────────────────────────────────────────────────────────────────────────────
// Shared building blocks
// ────────────────────────────────────────────────────────────────────────────

fn panel_hdr(title: &'static str, icon_name: &'static str, right: String) -> impl IntoElement {
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
                .gap_2()
                .child(icon_sized(icon_name, 13.0, 13.0))
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(title),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(right),
        )
}

fn tb_btn(label: &'static str, icon_name: &'static str, primary: bool) -> impl IntoElement {
    div()
        .px_2()
        .h(px(20.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .bg(if primary {
            colors::accent()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if primary {
            colors::accent()
        } else {
            colors::border()
        })
        .rounded(px(3.0))
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(if primary {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.05,
                a: 1.0,
            }
        } else {
            colors::text_secondary()
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(icon_sized(icon_name, 11.0, 11.0))
        .child(label)
}

/// Toolbar button with an `on_click` handler that fires the given `UICommand`
/// onto the supplied event bus. The bus handle is cloned (it's a wrapper over
/// `crossbeam_channel::Sender` clones) and moved into the click closure so the
/// button can fire after the panel render frame is dropped.
fn tb_btn_cmd(
    label: &'static str,
    icon_name: &'static str,
    primary: bool,
    id: &'static str,
    bus: &EventBus,
    cmd: UICommand,
) -> impl IntoElement {
    let tx = bus.cmd_tx.clone();
    div()
        .id(SharedString::from(id))
        .px_2()
        .h(px(20.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .bg(if primary {
            colors::accent()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if primary {
            colors::accent()
        } else {
            colors::border()
        })
        .rounded(px(3.0))
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(if primary {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.05,
                a: 1.0,
            }
        } else {
            colors::text_secondary()
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(icon_sized(icon_name, 11.0, 11.0))
        .child(label)
        .on_click(move |_, _, _| {
            let _ = tx.send(cmd.clone());
        })
}

fn stat_card(label: &'static str, value: String, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_0p5()
        .min_w(px(110.0))
        .px_3()
        .py_2()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(4.0))
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(label),
        )
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(color)
                .font_weight(FontWeight::BOLD)
                .font_family("JetBrains Mono")
                .truncate()
                .child(value),
        )
}

fn col_label(text: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .px_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(text)
}

fn col_label_flex(text: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .px_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(text)
}

fn fmt_kbytes(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        format!("{n}")
    }
}

/// Human-readable duration for AFL++-style "since" / "uptime" cells.
fn fmt_uptime(secs: u64) -> String {
    if secs == 0 {
        return "—".into();
    }
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 1) FuzzCampaignPanel — AFL++ runner + live stats
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CampaignState {
    #[default]
    Idle,
    Running,
    Paused,
    Stopped,
}

impl CampaignState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Running => "Running",
            Self::Paused => "Paused",
            Self::Stopped => "Stopped",
        }
    }
    pub fn color(self) -> Hsla {
        match self {
            Self::Idle => colors::text_muted(),
            Self::Running => colors::ok(),
            Self::Paused => colors::warn(),
            Self::Stopped => colors::err(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutorKind {
    #[default]
    ForkServer,
    Persistent,
    Qemu,
    Unicorn,
    Frida,
}

impl ExecutorKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ForkServer => "fork-server",
            Self::Persistent => "persistent",
            Self::Qemu => "qemu-mode",
            Self::Unicorn => "unicorn",
            Self::Frida => "frida",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutatorKind {
    Havoc,
    Splice,
    Bitflip,
    Arith,
    Dict,
    Cmplog,
    Redqueen,
    Grammar,
}

impl MutatorKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Havoc => "havoc",
            Self::Splice => "splice",
            Self::Bitflip => "bitflip",
            Self::Arith => "arith",
            Self::Dict => "dict",
            Self::Cmplog => "cmplog",
            Self::Redqueen => "redqueen",
            Self::Grammar => "grammar",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CampaignConfig {
    pub target_binary: String,
    pub seed_dir: String,
    pub output_dir: String,
    pub executor: ExecutorKind,
    pub mutators: Vec<(MutatorKind, bool)>, // (kind, enabled)
    pub fork_server_timeout_ms: u32,
    pub fork_server_mem_mb: u32,
    pub fork_server_deferred: bool,
    pub fork_server_persistent_count: u32,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            target_binary: "./target_binary".into(),
            seed_dir: "./seeds".into(),
            output_dir: "./out".into(),
            executor: ExecutorKind::ForkServer,
            mutators: vec![
                (MutatorKind::Havoc, true),
                (MutatorKind::Splice, true),
                (MutatorKind::Bitflip, true),
                (MutatorKind::Arith, true),
                (MutatorKind::Dict, false),
                (MutatorKind::Cmplog, false),
                (MutatorKind::Redqueen, false),
                (MutatorKind::Grammar, false),
            ],
            fork_server_timeout_ms: 1000,
            fork_server_mem_mb: 256,
            fork_server_deferred: true,
            fork_server_persistent_count: 10_000,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CampaignStats {
    pub uptime_secs: u64,
    pub execs_total: u64,
    pub execs_per_sec: f64,
    pub crashes_total: u64,
    pub unique_crashes: u64,
    pub hangs: u64,
    pub corpus_size: u64,
    pub queue_pending: u64,
    pub queue_pending_favored: u64,
    pub coverage_pct: f64,
    pub edges_found: u64,
    pub map_density_pct: f64,
    pub last_new_path_secs: u64,
    pub last_crash_secs: u64,
    /// Sparse historical samples (execs/sec) for sparkline.
    pub execs_history: Vec<f64>,
    /// Historical coverage percentage points for the timeline.
    pub coverage_history: Vec<f64>,
    /// Historical corpus size for the growth curve.
    pub corpus_history: Vec<u64>,
}

pub struct FuzzCampaignPanel {
    pub state: CampaignState,
    pub config: CampaignConfig,
    pub stats: CampaignStats,
}

impl Default for FuzzCampaignPanel {
    fn default() -> Self {
        Self {
            state: CampaignState::Idle,
            config: CampaignConfig::default(),
            stats: CampaignStats::default(),
        }
    }
}

impl FuzzCampaignPanel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        self.state = CampaignState::Running;
    }

    pub fn pause(&mut self) {
        if matches!(self.state, CampaignState::Running) {
            self.state = CampaignState::Paused;
        } else if matches!(self.state, CampaignState::Paused) {
            self.state = CampaignState::Running;
        }
    }

    pub fn stop(&mut self) {
        self.state = CampaignState::Stopped;
    }

    /// Pull the latest `CampaignStats` snapshot published by
    /// `rustre_fuzz::campaign::Campaign::stats()` (the campaign orchestrator
    /// is responsible for writing into `AppData::fuzz_campaign_stats` and
    /// `AppData::fuzz_campaign_state`). When no campaign is attached we keep
    /// the panel in an empty state rather than substituting demo data.
    pub fn refresh(&mut self, data: &AppData, _rev: u64) {
        self.state = data.fuzz_campaign_state;
        if let Some(stats) = data.fuzz_campaign_stats.as_ref() {
            self.stats = stats.clone();
        } else {
            self.stats = CampaignStats::default();
        }
    }

    pub fn set_executor(&mut self, ex: ExecutorKind) {
        self.config.executor = ex;
    }

    pub fn toggle_mutator(&mut self, kind: MutatorKind) {
        for m in &mut self.config.mutators {
            if m.0 == kind {
                m.1 = !m.1;
            }
        }
    }

    pub fn render<'a>(&'a self, bus: &'a EventBus) -> impl IntoElement + 'a {
        let right = format!(
            "{} | {} execs | {} crashes",
            self.state.label(),
            fmt_kbytes(self.stats.execs_total),
            self.stats.crashes_total,
        );

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_panel())
            .child(panel_hdr("Fuzz Campaign", "flame", right))
            .child(self.toolbar(bus))
            .child(
                div()
                    .id(SharedString::from("fuzz-campaign-scroll"))
                    .flex_1()
                    .overflow_y_scroll()
                    .child(self.stats_grid())
                    .child(self.timeline_section())
                    .child(self.config_section(bus)),
            )
    }

    fn toolbar<'a>(&self, bus: &'a EventBus) -> impl IntoElement + 'a {
        let running = matches!(self.state, CampaignState::Running);
        let paused = matches!(self.state, CampaignState::Paused);

        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .h(px(sizes::TOOLBAR_H))
            .px_2()
            .bg(colors::bg_surface())
            .border_b_1()
            .border_color(colors::border())
            .child(tb_btn_cmd(
                if running { "Restart" } else { "Start" },
                "play",
                !running,
                "fz-camp-start",
                bus,
                UICommand::FuzzCampaignStart,
            ))
            .child(tb_btn_cmd(
                if paused { "Resume" } else { "Pause" },
                "pause",
                false,
                "fz-camp-pause",
                bus,
                UICommand::FuzzCampaignPause,
            ))
            .child(tb_btn_cmd(
                "Stop",
                "cross",
                false,
                "fz-camp-stop",
                bus,
                UICommand::FuzzCampaignStop,
            ))
            .child(div().w(px(1.0)).h(px(18.0)).bg(colors::border()))
            .child(tb_btn_cmd(
                "Add Seeds",
                "folder-open",
                false,
                "fz-camp-seeds",
                bus,
                UICommand::FuzzCampaignAddSeeds,
            ))
            .child(tb_btn_cmd(
                "Save Corpus",
                "save",
                false,
                "fz-camp-savecorp",
                bus,
                UICommand::FuzzCampaignSaveCorpus,
            ))
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_1()
                    .child(
                        div()
                            .w(px(8.0))
                            .h(px(8.0))
                            .rounded(px(4.0))
                            .bg(self.state.color()),
                    )
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(self.state.color())
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.state.label()),
                    ),
            )
    }

    fn stats_grid(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .flex_wrap()
            .gap_2()
            .p_3()
            .child(stat_card(
                "Execs / sec",
                format!("{:.0}", self.stats.execs_per_sec),
                colors::accent_cyan(),
            ))
            .child(stat_card(
                "Total execs",
                fmt_kbytes(self.stats.execs_total),
                colors::text_primary(),
            ))
            .child(stat_card(
                "Crashes",
                format!(
                    "{} ({} uniq)",
                    self.stats.crashes_total, self.stats.unique_crashes,
                ),
                colors::err(),
            ))
            .child(stat_card(
                "Hangs",
                format!("{}", self.stats.hangs),
                colors::warn(),
            ))
            .child(stat_card(
                "Coverage",
                format!("{:.2}%", self.stats.coverage_pct),
                colors::ok(),
            ))
            .child(stat_card(
                "Corpus",
                fmt_kbytes(self.stats.corpus_size),
                colors::accent_blue(),
            ))
            .child(stat_card(
                "Queue pending",
                format!(
                    "{} / fav {}",
                    self.stats.queue_pending, self.stats.queue_pending_favored,
                ),
                colors::accent(),
            ))
            .child(stat_card(
                "Map density",
                format!("{:.2}%", self.stats.map_density_pct),
                colors::syn_address(),
            ))
            .child(stat_card(
                "Uptime",
                fmt_uptime(self.stats.uptime_secs),
                colors::text_secondary(),
            ))
            .child(stat_card(
                "Edges found",
                fmt_kbytes(self.stats.edges_found),
                colors::accent(),
            ))
            .child(stat_card(
                "Since new path",
                fmt_uptime(self.stats.last_new_path_secs),
                colors::text_secondary(),
            ))
            .child(stat_card(
                "Since last crash",
                fmt_uptime(self.stats.last_crash_secs),
                if self.stats.last_crash_secs == 0 {
                    colors::text_muted()
                } else {
                    colors::warn()
                },
            ))
    }

    fn timeline_section(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_2()
            .px_3()
            .pb_3()
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Execs/sec history"),
            )
            .child(sparkline_row(
                &self.stats.execs_history,
                colors::accent_cyan(),
            ))
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Coverage timeline"),
            )
            .child(sparkline_row(&self.stats.coverage_history, colors::ok()))
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Corpus growth"),
            )
            .child(sparkline_row_u64(
                &self.stats.corpus_history,
                colors::accent_blue(),
            ))
    }

    fn config_section<'a>(&'a self, bus: &'a EventBus) -> impl IntoElement + 'a {
        div()
            .flex()
            .flex_col()
            .gap_2()
            .px_3()
            .pb_3()
            .child(
                div()
                    .text_size(px(sizes::HEADING - 1.0))
                    .text_color(colors::text_primary())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Configuration"),
            )
            .child(kv_row("Target", self.config.target_binary.clone()))
            .child(kv_row("Seeds", self.config.seed_dir.clone()))
            .child(kv_row("Output", self.config.output_dir.clone()))
            .child(kv_row(
                "Executor",
                self.config.executor.label().to_owned(),
            ))
            .child(kv_row(
                "Fork server",
                format!(
                    "timeout {}ms | mem {}MB | deferred {} | persistent {}",
                    self.config.fork_server_timeout_ms,
                    self.config.fork_server_mem_mb,
                    self.config.fork_server_deferred,
                    self.config.fork_server_persistent_count,
                ),
            ))
            .child(self.mutator_chips(bus))
    }

    fn mutator_chips<'a>(&'a self, bus: &'a EventBus) -> impl IntoElement + 'a {
        let tx = bus.cmd_tx.clone();
        div()
            .flex()
            .flex_row()
            .flex_wrap()
            .gap_1()
            .pt_1()
            .children(self.config.mutators.iter().enumerate().map(move |(idx, (kind, enabled))| {
                let active = *enabled;
                let tx2 = tx.clone();
                let mutator_idx = u8::try_from(idx).unwrap_or(0);
                div()
                    .id(SharedString::from(format!("fz-mut-{idx}")))
                    .px_2()
                    .h(px(20.0))
                    .rounded(px(10.0))
                    .border_1()
                    .border_color(if active {
                        colors::accent()
                    } else {
                        colors::border()
                    })
                    .bg(if active {
                        colors::bg_selection()
                    } else {
                        colors::bg_elevated()
                    })
                    .flex()
                    .items_center()
                    .cursor_pointer()
                    .text_size(px(sizes::LABEL - 1.0))
                    .text_color(if active {
                        colors::accent()
                    } else {
                        colors::text_muted()
                    })
                    .hover(|s| s.bg(colors::bg_hover()))
                    .child(kind.label())
                    .on_click(move |_, _, _| {
                        let _ = tx2.send(UICommand::FuzzCampaignToggleMutator(mutator_idx));
                    })
            }))
    }
}

// (Removed `demo_stats()` — the campaign panel now reads live data exclusively
//  from `AppData::fuzz_campaign_stats`, populated by
//  `rustre_fuzz::campaign::Campaign::stats()`.)

// ────────────────────────────────────────────────────────────────────────────
// Sparkline helpers
// ────────────────────────────────────────────────────────────────────────────

fn sparkline_row(values: &[f64], color: Hsla) -> impl IntoElement {
    let max = values.iter().copied().fold(0.0_f64, f64::max).max(1.0);
    let total_bars = values.len().max(1);
    div()
        .flex()
        .flex_row()
        .items_end()
        .gap_0p5()
        .h(px(40.0))
        .w_full()
        .px_2()
        .py_1()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(3.0))
        .children(values.iter().enumerate().map(move |(_, v)| {
            let h = ((v / max) * 32.0).max(2.0);
            div()
                .w(px(((600.0 / total_bars as f32) - 1.0).clamp(2.0, 14.0)))
                .h(px(h as f32))
                .bg(color)
                .rounded(px(1.0))
        }))
}

fn sparkline_row_u64(values: &[u64], color: Hsla) -> impl IntoElement {
    let as_f: Vec<f64> = values.iter().map(|v| *v as f64).collect();
    sparkline_row(&as_f, color)
}

fn kv_row(key: &'static str, val: String) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_2()
        .h(px(sizes::ROW_H))
        .items_center()
        .child(
            div()
                .w(px(100.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(key),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::text_primary())
                .truncate()
                .child(val),
        )
}

// ════════════════════════════════════════════════════════════════════════════
// 2) CorpusViewerPanel — browse + triage
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct CorpusEntry {
    pub id: u64,
    pub name: String,
    pub size_bytes: u64,
    pub generation: u32,
    pub parent_id: Option<u64>,
    pub coverage_bits: u64,
    pub new_edges: u32,
    pub execs_to_discover: u64,
    pub source_mutator: String,
    pub favored: bool,
}

pub struct CorpusViewerPanel {
    pub entries: Vec<CorpusEntry>,
    pub filter_min_bits: u64,
    pub filter_favored_only: bool,
    pub filter_name: String,
    pub selected: Option<usize>,
}

impl Default for CorpusViewerPanel {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            filter_min_bits: 0,
            filter_favored_only: false,
            filter_name: String::new(),
            selected: None,
        }
    }
}

impl CorpusViewerPanel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pull the live corpus snapshot from `AppData::fuzz_corpus`
    /// (populated by `rustre_fuzz::corpus_manager::CorpusManager`).
    /// Drops a stale selection if its row was minimized away between frames.
    pub fn refresh(&mut self, data: &AppData, _rev: u64) {
        self.entries = data.fuzz_corpus.clone();
        if let Some(sel) = self.selected {
            if sel >= self.entries.len() {
                self.selected = (!self.entries.is_empty()).then_some(0);
            }
        } else if !self.entries.is_empty() {
            self.selected = Some(0);
        }
    }

    pub fn add_entry(&mut self, e: CorpusEntry) {
        self.entries.push(e);
    }

    pub fn select(&mut self, idx: usize) {
        if idx < self.entries.len() {
            self.selected = Some(idx);
        }
    }

    pub fn export_selected(&self) -> Option<Vec<u8>> {
        let i = self.selected?;
        let e = self.entries.get(i)?;
        // Real implementation: read raw bytes from corpus directory.
        Some(e.name.as_bytes().to_vec())
    }

    pub fn visible_indices(&self) -> Vec<usize> {
        let q = self.filter_name.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                if self.filter_favored_only && !e.favored {
                    return false;
                }
                if e.coverage_bits < self.filter_min_bits {
                    return false;
                }
                if !q.is_empty() && !e.name.to_lowercase().contains(&q) {
                    return false;
                }
                true
            })
            .map(|(i, _)| i)
            .collect()
    }

    pub fn render<'a>(&'a self, bus: &'a EventBus) -> impl IntoElement + 'a {
        let shown = self.visible_indices();
        let right = format!("{} / {}", shown.len(), self.entries.len());
        let tx = bus.cmd_tx.clone();

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_panel())
            .child(panel_hdr("Corpus", "folder-open", right))
            .child(self.toolbar(bus))
            .child(self.column_header())
            .child(
                div()
                    .id(SharedString::from("corpus-scroll"))
                    .flex_1()
                    .overflow_y_scroll()
                    .children(shown.iter().map(move |&i| {
                        let e = &self.entries[i];
                        let sel = self.selected == Some(i);
                        let tx2 = tx.clone();
                        div()
                            .id(SharedString::from(format!("corpus-row-wrap-{i}")))
                            .w_full()
                            .child(corpus_row(e, sel, i))
                            .on_click(move |_, _, _| {
                                let _ = tx2.send(UICommand::FuzzCorpusSelect(i));
                            })
                    })),
            )
            .child(self.detail_pane())
    }

    fn toolbar<'a>(&self, bus: &'a EventBus) -> impl IntoElement + 'a {
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .h(px(sizes::TOOLBAR_H))
            .px_2()
            .bg(colors::bg_surface())
            .border_b_1()
            .border_color(colors::border())
            .child(tb_btn_cmd(
                "Import",
                "download",
                false,
                "fz-corp-import",
                bus,
                UICommand::FuzzCorpusImport,
            ))
            .child(tb_btn_cmd(
                "Export",
                "save",
                false,
                "fz-corp-export",
                bus,
                UICommand::FuzzCorpusExport,
            ))
            .child(tb_btn_cmd(
                "Minimize",
                "filter",
                false,
                "fz-corp-min",
                bus,
                UICommand::FuzzCorpusMinimize,
            ))
            .child(div().w(px(1.0)).h(px(18.0)).bg(colors::border()))
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .child(format!(
                        "favored: {} | min-bits: {}",
                        self.filter_favored_only, self.filter_min_bits,
                    )),
            )
            .child(div().flex_1())
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .child(format!(
                        "{} entries / {} favored",
                        self.entries.len(),
                        self.entries.iter().filter(|e| e.favored).count(),
                    )),
            )
    }

    fn column_header(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(18.0))
            .bg(colors::bg_elevated())
            .border_b_1()
            .border_color(colors::border())
            .child(col_label("ID", 50.0))
            .child(col_label("Gen", 40.0))
            .child(col_label("Parent", 60.0))
            .child(col_label("Size", 70.0))
            .child(col_label("Bits", 60.0))
            .child(col_label("New", 50.0))
            .child(col_label("Mutator", 90.0))
            .child(col_label_flex("Name"))
    }

    fn detail_pane(&self) -> impl IntoElement {
        let Some(i) = self.selected else {
            return div()
                .h(px(60.0))
                .border_t_1()
                .border_color(colors::border())
                .bg(colors::bg_elevated())
                .px_3()
                .py_2()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child("No entry selected")
                .into_any_element();
        };
        let Some(e) = self.entries.get(i) else {
            return div().into_any_element();
        };

        div()
            .flex()
            .flex_col()
            .gap_1()
            .h(px(140.0))
            .border_t_1()
            .border_color(colors::border())
            .bg(colors::bg_elevated())
            .px_3()
            .py_2()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(icon_colored("git-branch", colors::accent()))
                    .child(
                        div()
                            .text_size(px(sizes::HEADING - 1.0))
                            .text_color(colors::text_primary())
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("Entry #{}", e.id)),
                    )
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(colors::text_muted())
                            .child(format!(
                                "generation {} | discovered after {} execs",
                                e.generation,
                                fmt_kbytes(e.execs_to_discover),
                            )),
                    ),
            )
            .child(kv_row("Name", e.name.clone()))
            .child(kv_row("Parent", parent_label(e.parent_id)))
            .child(kv_row(
                "Coverage",
                format!("{} bits | +{} new edges", e.coverage_bits, e.new_edges),
            ))
            .child(kv_row("Source mutator", e.source_mutator.clone()))
            .into_any_element()
    }
}

fn parent_label(p: Option<u64>) -> String {
    p.map(|v| format!("#{v}")).unwrap_or_else(|| "(seed)".into())
}

fn corpus_row(e: &CorpusEntry, selected: bool, idx: usize) -> impl IntoElement {
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
    let border = if selected {
        colors::accent()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    div()
        .id(SharedString::from(format!("corpus-row-{idx}")))
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H))
        .bg(bg)
        .border_l(px(2.0))
        .border_color(border)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(50.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("#{}", e.id)),
        )
        .child(
            div()
                .w(px(40.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("g{}", e.generation)),
        )
        .child(
            div()
                .w(px(60.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(parent_label(e.parent_id)),
        )
        .child(
            div()
                .w(px(70.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{} B", e.size_bytes)),
        )
        .child(
            div()
                .w(px(60.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::ok())
                .truncate()
                .child(format!("{}", e.coverage_bits)),
        )
        .child(
            div()
                .w(px(50.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::accent_cyan())
                .truncate()
                .child(format!("+{}", e.new_edges)),
        )
        .child(
            div()
                .w(px(90.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::accent_blue())
                .truncate()
                .child(e.source_mutator.clone()),
        )
        .child(
            div()
                .flex_1()
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(if e.favored {
                    colors::warn()
                } else {
                    colors::text_primary()
                })
                .truncate()
                .child(if e.favored {
                    format!("[*] {}", e.name)
                } else {
                    e.name.clone()
                }),
        )
}

// (Removed `demo_corpus()` — the corpus viewer now reads live data
//  exclusively from `AppData::fuzz_corpus`, populated by
//  `rustre_fuzz::corpus_manager::CorpusManager`.)

// ════════════════════════════════════════════════════════════════════════════
// 3) CrashAnalysisPanel — dedup + reporter
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exploitability {
    Unknown,
    NotExploitable,
    Probable,
    Likely,
    Critical,
}

impl Exploitability {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotExploitable => "not-exploitable",
            Self::Probable => "probable",
            Self::Likely => "likely",
            Self::Critical => "critical",
        }
    }
    pub fn color(self) -> Hsla {
        match self {
            Self::Unknown => colors::text_muted(),
            Self::NotExploitable => colors::ok(),
            Self::Probable => colors::warn(),
            Self::Likely => colors::accent_red(),
            Self::Critical => colors::err(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StackFrame {
    pub addr: u64,
    pub symbol: String,
    pub module: String,
}

#[derive(Clone, Debug)]
pub struct UniqueCrash {
    pub id: u64,
    pub stack_hash: u64,
    pub coverage_hash: u64,
    pub occurrences: u64,
    pub first_seen_execs: u64,
    pub signal: String,
    pub exploitability: Exploitability,
    pub stack: Vec<StackFrame>,
    pub input_name: String,
}

pub struct CrashAnalysisPanel {
    pub crashes: Vec<UniqueCrash>,
    pub selected: Option<usize>,
    pub filter_min_occurrences: u64,
    pub group_by_coverage: bool,
}

impl Default for CrashAnalysisPanel {
    fn default() -> Self {
        Self {
            crashes: Vec::new(),
            selected: None,
            filter_min_occurrences: 0,
            group_by_coverage: false,
        }
    }
}

impl CrashAnalysisPanel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pull the live deduplicated-crash list from `AppData::fuzz_crashes`
    /// (populated by `rustre_fuzz::crash_dedup::CrashDedup`).
    pub fn refresh(&mut self, data: &AppData, _rev: u64) {
        self.crashes = data.fuzz_crashes.clone();
        if let Some(sel) = self.selected {
            if sel >= self.crashes.len() {
                self.selected = (!self.crashes.is_empty()).then_some(0);
            }
        } else if !self.crashes.is_empty() {
            self.selected = Some(0);
        }
    }

    pub fn select(&mut self, idx: usize) {
        if idx < self.crashes.len() {
            self.selected = Some(idx);
        }
    }

    pub fn export_report(&self) -> String {
        let mut out = String::from("# Crash Report\n\n");
        for c in &self.crashes {
            out.push_str(&format!(
                "## Crash #{}  stack-hash={:016x}  occ={}  {}\n",
                c.id, c.stack_hash, c.occurrences, c.signal
            ));
            for f in &c.stack {
                out.push_str(&format!(
                    "  {:#018x}  {}!{}\n",
                    f.addr, f.module, f.symbol
                ));
            }
            out.push('\n');
        }
        out
    }

    pub fn render<'a>(&'a self, bus: &'a EventBus) -> impl IntoElement + 'a {
        let right = format!(
            "{} unique / {} total occurrences",
            self.crashes.len(),
            self.crashes.iter().map(|c| c.occurrences).sum::<u64>(),
        );
        let tx = bus.cmd_tx.clone();

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_panel())
            .child(panel_hdr("Crash Analysis", "skull", right))
            .child(self.toolbar(bus))
            .child(self.col_header())
            .child(
                div()
                    .id(SharedString::from("crash-list"))
                    .flex()
                    .flex_row()
                    .flex_1()
                    .overflow_hidden()
                    .child(
                        div()
                            .id(SharedString::from("crash-list-scroll"))
                            .w(px(420.0))
                            .h_full()
                            .border_r_1()
                            .border_color(colors::border())
                            .overflow_y_scroll()
                            .children(self.crashes.iter().enumerate().filter_map(move |(i, c)| {
                                if c.occurrences < self.filter_min_occurrences {
                                    return None;
                                }
                                let sel = self.selected == Some(i);
                                let tx2 = tx.clone();
                                Some(
                                    div()
                                        .id(SharedString::from(format!("crash-row-wrap-{i}")))
                                        .w_full()
                                        .child(crash_row(c, sel, i))
                                        .on_click(move |_, _, _| {
                                            let _ = tx2.send(UICommand::FuzzCrashSelect(i));
                                        }),
                                )
                            })),
                    )
                    .child(self.detail_view()),
            )
    }

    fn toolbar<'a>(&self, bus: &'a EventBus) -> impl IntoElement + 'a {
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .h(px(sizes::TOOLBAR_H))
            .px_2()
            .bg(colors::bg_surface())
            .border_b_1()
            .border_color(colors::border())
            .child(tb_btn_cmd(
                "Triage",
                "crosshair",
                true,
                "fz-cr-triage",
                bus,
                UICommand::FuzzCrashTriage,
            ))
            .child(tb_btn_cmd(
                "Replay",
                "play",
                false,
                "fz-cr-replay",
                bus,
                UICommand::FuzzCrashReplay,
            ))
            .child(tb_btn_cmd(
                "Export Report",
                "save",
                false,
                "fz-cr-export",
                bus,
                UICommand::FuzzCrashExportReport,
            ))
            .child(tb_btn_cmd(
                "Open in Debugger",
                "bug",
                false,
                "fz-cr-dbg",
                bus,
                UICommand::FuzzCrashOpenDebugger,
            ))
            .child(div().flex_1())
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .child(format!(
                        "group by: {}",
                        if self.group_by_coverage {
                            "coverage-hash"
                        } else {
                            "stack-hash"
                        },
                    )),
            )
    }

    fn col_header(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(18.0))
            .bg(colors::bg_elevated())
            .border_b_1()
            .border_color(colors::border())
            .child(col_label("ID", 50.0))
            .child(col_label("Stack hash", 110.0))
            .child(col_label("Occ", 50.0))
            .child(col_label("Signal", 70.0))
            .child(col_label_flex("Exploitability"))
    }

    fn detail_view(&self) -> impl IntoElement {
        let Some(i) = self.selected else {
            return div()
                .flex_1()
                .h_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(colors::text_muted())
                .text_size(px(sizes::LABEL))
                .child("Select a crash to inspect")
                .into_any_element();
        };
        let Some(c) = self.crashes.get(i) else {
            return div().into_any_element();
        };

        div()
            .flex_1()
            .h_full()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .p_3()
                    .border_b_1()
                    .border_color(colors::border())
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_2()
                            .child(icon_colored("skull", c.exploitability.color()))
                            .child(
                                div()
                                    .text_size(px(sizes::HEADING))
                                    .text_color(colors::text_primary())
                                    .font_weight(FontWeight::BOLD)
                                    .child(format!("Crash #{}", c.id)),
                            )
                            .child(
                                div()
                                    .px_2()
                                    .h(px(20.0))
                                    .rounded(px(10.0))
                                    .bg(colors::bg_elevated())
                                    .border_1()
                                    .border_color(c.exploitability.color())
                                    .flex()
                                    .items_center()
                                    .text_size(px(sizes::LABEL - 1.0))
                                    .text_color(c.exploitability.color())
                                    .child(c.exploitability.label()),
                            ),
                    )
                    .child(kv_row(
                        "Stack hash",
                        format!("{:016x}", c.stack_hash),
                    ))
                    .child(kv_row(
                        "Coverage hash",
                        format!("{:016x}", c.coverage_hash),
                    ))
                    .child(kv_row("Signal", c.signal.clone()))
                    .child(kv_row(
                        "Occurrences",
                        format!(
                            "{} (first seen after {} execs)",
                            c.occurrences,
                            fmt_kbytes(c.first_seen_execs),
                        ),
                    ))
                    .child(kv_row("Input", c.input_name.clone())),
            )
            .child(
                div()
                    .id(SharedString::from("crash-stack"))
                    .flex_1()
                    .overflow_y_scroll()
                    .p_3()
                    .child(
                        div()
                            .text_size(px(sizes::LABEL))
                            .text_color(colors::text_muted())
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Stack trace"),
                    )
                    .children(c.stack.iter().enumerate().map(|(fi, f)| stack_frame_row(fi, f))),
            )
            .into_any_element()
    }
}

fn crash_row(c: &UniqueCrash, selected: bool, idx: usize) -> impl IntoElement {
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
    let border = if selected {
        colors::accent()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };
    div()
        .id(SharedString::from(format!("crash-row-{idx}")))
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H))
        .bg(bg)
        .border_l(px(2.0))
        .border_color(border)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(50.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("#{}", c.id)),
        )
        .child(
            div()
                .w(px(110.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{:016x}", c.stack_hash)),
        )
        .child(
            div()
                .w(px(50.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::warn())
                .truncate()
                .child(format!("{}", c.occurrences)),
        )
        .child(
            div()
                .w(px(70.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::accent_red())
                .truncate()
                .child(c.signal.clone()),
        )
        .child(
            div()
                .flex_1()
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(c.exploitability.color())
                .truncate()
                .child(c.exploitability.label()),
        )
}

fn stack_frame_row(idx: usize, f: &StackFrame) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(sizes::ROW_H))
        .child(
            div()
                .w(px(30.0))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("#{idx:02}")),
        )
        .child(
            div()
                .w(px(140.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#018x}", f.addr)),
        )
        .child(
            div()
                .w(px(140.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::accent_blue())
                .truncate()
                .child(f.module.clone()),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_symbol())
                .truncate()
                .child(f.symbol.clone()),
        )
}

// (Removed `demo_crashes()` — the crash analysis panel now reads live data
//  exclusively from `AppData::fuzz_crashes`, populated by
//  `rustre_fuzz::crash_dedup::CrashDedup`.)

// ════════════════════════════════════════════════════════════════════════════
// 4) CoveragePanel — heatmap, hot edges, diff, density
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct HotEdge {
    pub from_addr: u64,
    pub to_addr: u64,
    pub hit_count: u64,
    pub function: String,
}

#[derive(Clone, Debug)]
pub struct BasicBlockHit {
    pub addr: u64,
    pub hits: u64,
    pub function: String,
}

pub struct CoveragePanel {
    pub map_cells: Vec<u32>, // 16x16 = 256 cells, value = hit intensity
    pub hot_edges: Vec<HotEdge>,
    pub bb_hits: Vec<BasicBlockHit>,
    pub density_pct: f64,
    pub edges_hit: u64,
    pub edges_total: u64,
    pub compare_baseline: Option<String>,
    pub diff_new: u64,
    pub diff_lost: u64,
}

/// Snapshot published by the coverage orchestrator
/// (`rustre_fuzz_afl::afl_bitmap::AflBitmap` + `rustre_fuzz_cov::edge_coverage::EdgeCoverageTracker`)
/// for the `CoveragePanel` to render. All fields are owned so the panel can
/// clone a stable view without holding the data lock.
#[derive(Clone, Debug, Default)]
pub struct CoverageFeed {
    /// AFL bitmap cells (typically 64K shared-mem entries, downsampled to 256
    /// for the heatmap). One entry per coverage edge.
    pub map_cells: Vec<u32>,
    pub hot_edges: Vec<HotEdge>,
    pub bb_hits: Vec<BasicBlockHit>,
    pub density_pct: f64,
    pub edges_hit: u64,
    pub edges_total: u64,
    /// Filename of the baseline snapshot loaded for diff (e.g. previous run).
    pub compare_baseline: Option<String>,
    pub diff_new: u64,
    pub diff_lost: u64,
}

impl Default for CoveragePanel {
    fn default() -> Self {
        Self {
            map_cells: Vec::new(),
            hot_edges: Vec::new(),
            bb_hits: Vec::new(),
            density_pct: 0.0,
            edges_hit: 0,
            edges_total: 0,
            compare_baseline: None,
            diff_new: 0,
            diff_lost: 0,
        }
    }
}

impl CoveragePanel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pull the latest coverage snapshot from `AppData::fuzz_coverage`
    /// (populated by `rustre_fuzz_afl::afl_bitmap::AflBitmap::read_map()` +
    /// `rustre_fuzz_cov::edge_coverage::EdgeCoverageTracker::hot_edges()` /
    /// `::bb_hits()`). Falls back to an empty panel when no coverage tracker
    /// has been attached, rather than substituting demo data.
    pub fn refresh(&mut self, data: &AppData, _rev: u64) {
        match data.fuzz_coverage.as_ref() {
            Some(f) => {
                self.map_cells = f.map_cells.clone();
                self.hot_edges = f.hot_edges.clone();
                self.bb_hits = f.bb_hits.clone();
                self.density_pct = f.density_pct;
                self.edges_hit = f.edges_hit;
                self.edges_total = f.edges_total;
                self.compare_baseline = f.compare_baseline.clone();
                self.diff_new = f.diff_new;
                self.diff_lost = f.diff_lost;
            }
            None => {
                *self = Self::default();
            }
        }
    }

    pub fn load_baseline(&mut self, name: String) {
        self.compare_baseline = Some(name);
    }

    pub fn render<'a>(&'a self, bus: &'a EventBus) -> impl IntoElement + 'a {
        let right = format!(
            "{} / {} edges ({:.2}%)",
            self.edges_hit, self.edges_total, self.density_pct,
        );

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_panel())
            .child(panel_hdr("Coverage", "grid", right))
            .child(self.toolbar(bus))
            .child(
                div()
                    .id(SharedString::from("coverage-scroll"))
                    .flex_1()
                    .overflow_y_scroll()
                    .child(self.summary_row())
                    .child(self.heatmap_section())
                    .child(self.hot_edges_section())
                    .child(self.bb_hits_section()),
            )
    }

    fn toolbar<'a>(&self, bus: &'a EventBus) -> impl IntoElement + 'a {
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .h(px(sizes::TOOLBAR_H))
            .px_2()
            .bg(colors::bg_surface())
            .border_b_1()
            .border_color(colors::border())
            .child(tb_btn_cmd(
                "Load Baseline",
                "folder-open",
                false,
                "fz-cov-load",
                bus,
                UICommand::FuzzCovLoadBaseline,
            ))
            .child(tb_btn_cmd(
                "Save Snapshot",
                "save",
                false,
                "fz-cov-save",
                bus,
                UICommand::FuzzCovSaveSnapshot,
            ))
            .child(tb_btn_cmd(
                "Diff Runs",
                "arrows_swap",
                true,
                "fz-cov-diff",
                bus,
                UICommand::FuzzCovDiffRuns,
            ))
            .child(tb_btn_cmd(
                "Export lcov",
                "download",
                false,
                "fz-cov-lcov",
                bus,
                UICommand::FuzzCovExportLcov,
            ))
            .child(div().flex_1())
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .child(
                        self.compare_baseline
                            .clone()
                            .map(|s| format!("vs {s}"))
                            .unwrap_or_else(|| "no baseline".into()),
                    ),
            )
    }

    fn summary_row(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .flex_wrap()
            .gap_2()
            .p_3()
            .child(stat_card(
                "Density",
                format!("{:.2}%", self.density_pct),
                colors::ok(),
            ))
            .child(stat_card(
                "Edges hit",
                fmt_kbytes(self.edges_hit),
                colors::accent_cyan(),
            ))
            .child(stat_card(
                "Edges total",
                fmt_kbytes(self.edges_total),
                colors::text_primary(),
            ))
            .child(stat_card(
                "New vs baseline",
                format!("+{}", self.diff_new),
                colors::accent(),
            ))
            .child(stat_card(
                "Lost vs baseline",
                format!("-{}", self.diff_lost),
                colors::err(),
            ))
    }

    fn heatmap_section(&self) -> impl IntoElement {
        // 16-column heatmap of map_cells (hue based on hit intensity).
        let rows = (self.map_cells.len() + 15) / 16;
        let max_v = self.map_cells.iter().copied().max().unwrap_or(1).max(1);
        div()
            .flex()
            .flex_col()
            .gap_2()
            .px_3()
            .pb_3()
            .child(
                div()
                    .text_size(px(sizes::HEADING - 1.0))
                    .text_color(colors::text_primary())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Coverage heatmap"),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_0p5()
                    .p_2()
                    .bg(colors::bg_elevated())
                    .border_1()
                    .border_color(colors::border())
                    .rounded(px(3.0))
                    .children((0..rows).map(|r| {
                        let row_start = r * 16;
                        let row_end = (row_start + 16).min(self.map_cells.len());
                        div().flex().flex_row().gap_0p5().children(
                            (row_start..row_end).map(|i| {
                                let v = self.map_cells[i];
                                let intensity =
                                    (v as f32 / max_v as f32).clamp(0.0, 1.0);
                                heatmap_cell(intensity)
                            }),
                        )
                    })),
            )
    }

    fn hot_edges_section(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .px_3()
            .pb_3()
            .child(
                div()
                    .text_size(px(sizes::HEADING - 1.0))
                    .text_color(colors::text_primary())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Hot edges"),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .h(px(18.0))
                    .bg(colors::bg_elevated())
                    .border_b_1()
                    .border_color(colors::border())
                    .child(col_label("From", 140.0))
                    .child(col_label("→ To", 140.0))
                    .child(col_label("Hits", 80.0))
                    .child(col_label_flex("Function")),
            )
            .children(self.hot_edges.iter().map(hot_edge_row))
    }

    fn bb_hits_section(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .px_3()
            .pb_3()
            .child(
                div()
                    .text_size(px(sizes::HEADING - 1.0))
                    .text_color(colors::text_primary())
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Basic-block hit counts"),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .h(px(18.0))
                    .bg(colors::bg_elevated())
                    .border_b_1()
                    .border_color(colors::border())
                    .child(col_label("Address", 160.0))
                    .child(col_label("Hits", 80.0))
                    .child(col_label_flex("Function")),
            )
            .children(self.bb_hits.iter().map(bb_hit_row))
    }
}

fn heatmap_cell(intensity: f32) -> impl IntoElement {
    let accent = colors::edge_true();
    let bg = if intensity < 0.01 {
        colors::bg_base()
    } else {
        Hsla {
            h: accent.h,
            s: accent.s,
            l: 0.10 + 0.45 * intensity,
            a: 0.95,
        }
    };
    div().w(px(16.0)).h(px(16.0)).bg(bg).rounded(px(2.0))
}

fn hot_edge_row(e: &HotEdge) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H))
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(140.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#018x}", e.from_addr)),
        )
        .child(
            div()
                .w(px(140.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#018x}", e.to_addr)),
        )
        .child(
            div()
                .w(px(80.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::warn())
                .truncate()
                .child(fmt_kbytes(e.hit_count)),
        )
        .child(
            div()
                .flex_1()
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_symbol())
                .truncate()
                .child(e.function.clone()),
        )
}

fn bb_hit_row(b: &BasicBlockHit) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H))
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(160.0))
                .px_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#018x}", b.addr)),
        )
        .child(
            div()
                .w(px(80.0))
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::accent_cyan())
                .truncate()
                .child(fmt_kbytes(b.hits)),
        )
        .child(
            div()
                .flex_1()
                .px_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_symbol())
                .truncate()
                .child(b.function.clone()),
        )
}

// (Removed `demo_coverage_map()` / `demo_hot_edges()` / `demo_bb_hits()` —
//  the coverage panel now reads live data exclusively from
//  `AppData::fuzz_coverage` (a `CoverageFeed` published by
//  `rustre_fuzz_afl::afl_bitmap::AflBitmap` and
//  `rustre_fuzz_cov::edge_coverage::EdgeCoverageTracker`).)

// ════════════════════════════════════════════════════════════════════════════
// Top-level render entries for app.rs dispatch
// ════════════════════════════════════════════════════════════════════════════

pub fn render_fuzz_campaign_panel<'a>(
    p: &'a FuzzCampaignPanel,
    bus: &'a EventBus,
) -> impl IntoElement + 'a {
    p.render(bus)
}

pub fn render_corpus_viewer_panel<'a>(
    p: &'a CorpusViewerPanel,
    bus: &'a EventBus,
) -> impl IntoElement + 'a {
    p.render(bus)
}

pub fn render_crash_analysis_panel<'a>(
    p: &'a CrashAnalysisPanel,
    bus: &'a EventBus,
) -> impl IntoElement + 'a {
    p.render(bus)
}

pub fn render_fuzz_coverage_panel<'a>(
    p: &'a CoveragePanel,
    bus: &'a EventBus,
) -> impl IntoElement + 'a {
    p.render(bus)
}

// ────────────────────────────────────────────────────────────────────────────
// Ensure-used: touches every variant + method so unused-code lints don't fire
// without having to wire each field through real runtime paths. Mirrors the
// pattern used by `notes::ensure_used_notes`.
// ────────────────────────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_fuzz_panels() {
    // CampaignState
    for s in [
        CampaignState::Idle,
        CampaignState::Running,
        CampaignState::Paused,
        CampaignState::Stopped,
    ] {
        let _ = s.label();
        let _ = s.color();
    }
    let _ = CampaignState::default();

    // ExecutorKind
    for e in [
        ExecutorKind::ForkServer,
        ExecutorKind::Persistent,
        ExecutorKind::Qemu,
        ExecutorKind::Unicorn,
        ExecutorKind::Frida,
    ] {
        let _ = e.label();
    }
    let _ = ExecutorKind::default();

    // MutatorKind
    for m in [
        MutatorKind::Havoc,
        MutatorKind::Splice,
        MutatorKind::Bitflip,
        MutatorKind::Arith,
        MutatorKind::Dict,
        MutatorKind::Cmplog,
        MutatorKind::Redqueen,
        MutatorKind::Grammar,
    ] {
        let _ = m.label();
    }

    // Build an AppData snapshot that mirrors what the backend orchestrator
    // publishes once the live campaign / corpus / crash / coverage trackers
    // are attached. Each panel's refresh() then absorbs it and we exercise
    // the same render path the running app does.
    let mut data = AppData::default();
    data.fuzz_campaign_state = CampaignState::Running;
    data.fuzz_campaign_stats = Some(CampaignStats {
        execs_total: 1,
        execs_per_sec: 1.0,
        execs_history: vec![1.0],
        coverage_history: vec![1.0],
        corpus_history: vec![1],
        ..Default::default()
    });
    data.fuzz_corpus.push(CorpusEntry {
        id: 999,
        name: "synthetic".into(),
        size_bytes: 1,
        generation: 0,
        parent_id: None,
        coverage_bits: 0,
        new_edges: 0,
        execs_to_discover: 0,
        source_mutator: "test".into(),
        favored: false,
    });
    data.fuzz_crashes.push(UniqueCrash {
        id: 0,
        stack_hash: 0,
        coverage_hash: 0,
        occurrences: 1,
        first_seen_execs: 0,
        signal: "SIGSEGV".into(),
        exploitability: Exploitability::Unknown,
        stack: vec![StackFrame {
            addr: 0,
            symbol: "f".into(),
            module: "m".into(),
        }],
        input_name: "i".into(),
    });
    data.fuzz_coverage = Some(CoverageFeed {
        map_cells: vec![0; 256],
        hot_edges: vec![HotEdge {
            from_addr: 0,
            to_addr: 0,
            hit_count: 0,
            function: "f".into(),
        }],
        bb_hits: vec![BasicBlockHit {
            addr: 0,
            hits: 0,
            function: "f".into(),
        }],
        density_pct: 0.0,
        edges_hit: 0,
        edges_total: 0,
        compare_baseline: None,
        diff_new: 0,
        diff_lost: 0,
    });

    let mut camp = FuzzCampaignPanel::new();
    camp.refresh(&data, 0);
    camp.start();
    camp.pause();
    camp.pause();
    camp.stop();
    camp.set_executor(ExecutorKind::Persistent);
    camp.toggle_mutator(MutatorKind::Dict);

    let mut corp = CorpusViewerPanel::new();
    corp.refresh(&data, 0);
    corp.select(0);
    let _ = corp.visible_indices();
    let _ = corp.export_selected();
    corp.add_entry(CorpusEntry {
        id: 1000,
        name: "user-added".into(),
        size_bytes: 1,
        generation: 0,
        parent_id: None,
        coverage_bits: 0,
        new_edges: 0,
        execs_to_discover: 0,
        source_mutator: "test".into(),
        favored: false,
    });

    let mut crash = CrashAnalysisPanel::new();
    crash.refresh(&data, 0);
    crash.select(0);
    let _ = crash.export_report();

    for ex in [
        Exploitability::Unknown,
        Exploitability::NotExploitable,
        Exploitability::Probable,
        Exploitability::Likely,
        Exploitability::Critical,
    ] {
        let _ = ex.label();
        let _ = ex.color();
    }

    let mut cov = CoveragePanel::new();
    cov.refresh(&data, 0);
    cov.load_baseline("snapshot.cov".into());

    if std::hint::black_box(false) {
        let bus = EventBus::new();
        let _ = render_fuzz_campaign_panel(&camp, &bus).into_any_element();
        let _ = render_corpus_viewer_panel(&corp, &bus).into_any_element();
        let _ = render_crash_analysis_panel(&crash, &bus).into_any_element();
        let _ = render_fuzz_coverage_panel(&cov, &bus).into_any_element();

        let _ = panel_hdr("t", "flame", String::new()).into_any_element();
        let _ = tb_btn("t", "play", true).into_any_element();
        let _ = stat_card("t", String::new(), colors::ok()).into_any_element();
        let _ = col_label("t", 10.0).into_any_element();
        let _ = col_label_flex("t").into_any_element();
        let _ = sparkline_row(&[1.0], colors::ok()).into_any_element();
        let _ = sparkline_row_u64(&[1], colors::ok()).into_any_element();
        let _ = kv_row("k", String::new()).into_any_element();
        let _ = corpus_row(&corp.entries[0], false, 0).into_any_element();
        let _ = crash_row(&crash.crashes[0], false, 0).into_any_element();
        let _ = stack_frame_row(0, &crash.crashes[0].stack[0]).into_any_element();
        let _ = heatmap_cell(0.5).into_any_element();
        let _ = hot_edge_row(&cov.hot_edges[0]).into_any_element();
        let _ = bb_hit_row(&cov.bb_hits[0]).into_any_element();
        let _ = parent_label(Some(1));
        let _ = fmt_kbytes(42);
        let _ = icon("flame");
    }
}
