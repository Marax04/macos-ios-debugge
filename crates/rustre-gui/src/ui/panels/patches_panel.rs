// ============================================================================
// ui/panels/patches_panel.rs — Extended patches panel (stacked patches, hex
// diff preview, undo history, import/export to PE-rebuild formats).
//
// Ported from the legacy eframe/egui prototype to the current zyphora GPUI
// API. All data structures and business logic are preserved verbatim; only
// the UI layer was rewritten on top of `gpui::div` element builders. The
// live counterpart `patches.rs` is a slimmer, list-only view; this panel is
// the "patch manager" surface (manual add, multi-format export, undo).
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, Styled,
};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Data types — preserved 1:1 from the legacy panel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchStatus {
    Applied,
    Reverted,
    Pending,
    VerifyFailed,
}

impl PatchStatus {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Applied => "Applied",
            Self::Reverted => "Reverted",
            Self::Pending => "Pending",
            Self::VerifyFailed => "Mismatch",
        }
    }

    pub const fn color(&self) -> Hsla {
        match self {
            Self::Applied => colors::ok(),
            Self::Reverted => colors::text_muted(),
            Self::Pending => colors::warn(),
            Self::VerifyFailed => colors::err(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchSource {
    Manual,
    Imported,
    Script,
    Debugger,
}

impl PatchSource {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Manual => "Manual",
            Self::Imported => "Imported",
            Self::Script => "Script",
            Self::Debugger => "Debugger",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Patch {
    pub id: u64,
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub patched_bytes: Vec<u8>,
    pub size: usize,
    pub description: String,
    pub status: PatchStatus,
    pub source: PatchSource,
    pub applied_at: u64,
    pub tags: Vec<String>,
}

impl Patch {
    pub fn byte_diff(&self) -> Vec<ByteDiff> {
        let max_len = self.original_bytes.len().max(self.patched_bytes.len());
        (0..max_len)
            .map(|i| {
                let orig = self.original_bytes.get(i).copied();
                let patched = self.patched_bytes.get(i).copied();
                ByteDiff {
                    offset: i,
                    original: orig,
                    patched,
                    changed: orig != patched,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ByteDiff {
    pub offset: usize,
    pub original: Option<u8>,
    pub patched: Option<u8>,
    pub changed: bool,
}

#[derive(Debug, Clone)]
pub struct HistorySnapshot {
    pub timestamp: u64,
    pub label: String,
    pub patch_states: Vec<(u64, PatchStatus)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFormat {
    BinaryPatch,
    PythonPatcher,
    CHexArray,
    IdaPatchFormat,
    Xdelta,
}

impl ExportFormat {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::BinaryPatch => "Binary Patch (.patch)",
            Self::PythonPatcher => "Python Patcher (.py)",
            Self::CHexArray => "C Hex Array (.c)",
            Self::IdaPatchFormat => "IDA Patch Format (.dif)",
            Self::Xdelta => "xdelta (.xdelta)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportFormat {
    CustomPatch,
    IdaPatchFormat,
    Xdelta,
}

impl ImportFormat {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CustomPatch => "Custom Patch (.patch)",
            Self::IdaPatchFormat => "IDA Patch Format (.dif)",
            Self::Xdelta => "xdelta (.xdelta)",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddPatchForm {
    pub address_str: String,
    pub original_hex: String,
    pub patched_hex: String,
    pub description: String,
    pub error: Option<String>,
}

impl AddPatchForm {
    pub fn parse_address(&self) -> Option<u64> {
        let s = self.address_str.trim().replace("0x", "").replace("0X", "");
        u64::from_str_radix(&s, 16).ok()
    }

    pub fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() % 2 != 0 {
            return None;
        }
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
            .collect()
    }

    pub fn validate(&self) -> Result<(u64, Vec<u8>, Vec<u8>), String> {
        let addr = self.parse_address().ok_or("Invalid address")?;
        let orig =
            Self::parse_hex_bytes(&self.original_hex).ok_or("Invalid original hex bytes")?;
        let patched =
            Self::parse_hex_bytes(&self.patched_hex).ok_or("Invalid patched hex bytes")?;
        if orig.is_empty() && patched.is_empty() {
            return Err("Both byte sequences are empty".into());
        }
        Ok((addr, orig, patched))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveView {
    PatchList,
    AddPatch,
    Preview,
    UndoHistory,
}

// ---------------------------------------------------------------------------
// PatchesPanel — owns all extended-panel state (kept identical to legacy)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PatchesPanel {
    pub patches: Vec<Patch>,
    pub selected_idx: Option<usize>,
    pub selected_idxs: Vec<usize>,

    pub active_view: ActiveView,

    pub filter_text: String,
    pub filter_status: Option<PatchStatus>,
    pub sort_by_address: bool,

    pub add_form: AddPatchForm,

    pub undo_history: Vec<HistorySnapshot>,
    pub current_history_idx: usize,

    pub show_export_dialog: bool,
    pub export_format: ExportFormat,
    pub export_path: String,

    pub show_import_dialog: bool,
    pub import_format: ImportFormat,
    pub import_path: String,

    pub is_verifying: bool,
    pub verify_results: Vec<(u64, bool)>,

    pub navigate_to_address: Option<u64>,

    pub next_id: u64,
}

impl Default for PatchesPanel {
    fn default() -> Self {
        // Start empty. Real patches flow in from `AppData::patches` via
        // `merge_live_patches()` at render time. The legacy demo seed
        // (`generate_demo_patches`) is retained as a developer-facing fixture
        // for the ensure-used coverage path only — production never calls it.
        let patches: Vec<Patch> = Vec::new();
        let snapshot = HistorySnapshot {
            timestamp: unix_now(),
            label: "Initial state".into(),
            patch_states: patches.iter().map(|p| (p.id, p.status.clone())).collect(),
        };
        Self {
            patches,
            selected_idx: None,
            selected_idxs: Vec::new(),
            active_view: ActiveView::PatchList,
            filter_text: String::new(),
            filter_status: None,
            sort_by_address: true,
            add_form: AddPatchForm::default(),
            undo_history: vec![snapshot],
            current_history_idx: 0,
            show_export_dialog: false,
            export_format: ExportFormat::BinaryPatch,
            export_path: String::new(),
            show_import_dialog: false,
            import_format: ImportFormat::CustomPatch,
            import_path: String::new(),
            is_verifying: false,
            verify_results: Vec::new(),
            navigate_to_address: None,
            next_id: 10,
        }
    }
}

impl PatchesPanel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn take_navigate_address(&mut self) -> Option<u64> {
        self.navigate_to_address.take()
    }

    pub fn apply_all(&mut self) {
        for p in &mut self.patches {
            if p.status == PatchStatus::Pending || p.status == PatchStatus::Reverted {
                p.status = PatchStatus::Applied;
            }
        }
        self.push_history("Apply all patches");
    }

    pub fn revert_all(&mut self) {
        for p in &mut self.patches {
            if p.status == PatchStatus::Applied {
                p.status = PatchStatus::Reverted;
            }
        }
        self.push_history("Revert all patches");
    }

    pub fn apply_selected(&mut self, idxs: &[usize]) {
        for &i in idxs {
            if i < self.patches.len() {
                self.patches[i].status = PatchStatus::Applied;
            }
        }
        self.push_history("Apply selected");
    }

    pub fn revert_selected(&mut self, idxs: &[usize]) {
        for &i in idxs {
            if i < self.patches.len() {
                self.patches[i].status = PatchStatus::Reverted;
            }
        }
        self.push_history("Revert selected");
    }

    pub fn verify_patches(&mut self) {
        self.is_verifying = true;
        self.verify_results = self
            .patches
            .iter()
            .map(|p| (p.id, p.status != PatchStatus::VerifyFailed))
            .collect();
        self.is_verifying = false;
    }

    pub fn push_history(&mut self, label: &str) {
        let snapshot = HistorySnapshot {
            timestamp: unix_now(),
            label: label.to_string(),
            patch_states: self.patches.iter().map(|p| (p.id, p.status.clone())).collect(),
        };
        self.undo_history.truncate(self.current_history_idx + 1);
        self.undo_history.push(snapshot);
        self.current_history_idx = self.undo_history.len() - 1;
    }

    pub fn restore_snapshot(&mut self, snapshot_idx: usize) {
        if snapshot_idx >= self.undo_history.len() {
            return;
        }
        let states = self.undo_history[snapshot_idx].patch_states.clone();
        for (id, status) in states {
            if let Some(p) = self.patches.iter_mut().find(|p| p.id == id) {
                p.status = status;
            }
        }
        self.current_history_idx = snapshot_idx;
    }

    pub fn generate_export_preview(&self) -> String {
        let applied: Vec<&Patch> = self
            .patches
            .iter()
            .filter(|p| p.status == PatchStatus::Applied)
            .collect();
        match self.export_format {
            ExportFormat::PythonPatcher => {
                use std::fmt::Write as _;
                let mut out = String::from("import sys\n\nwith open(sys.argv[1], 'r+b') as f:\n");
                for p in &applied {
                    let mut patched_hex = String::new();
                    for b in &p.patched_bytes {
                        let _ = write!(patched_hex, "\\x{b:02x}");
                    }
                    let _ = writeln!(
                        out,
                        "    f.seek(0x{:X}); f.write(b\"{}\")",
                        p.address, patched_hex
                    );
                }
                out
            }
            ExportFormat::CHexArray => {
                use std::fmt::Write as _;
                let mut out = String::from(
                    "typedef struct { size_t offset; const char *bytes; size_t len; } Patch;\nPatch patches[] = {\n",
                );
                for p in &applied {
                    let mut bytes = String::new();
                    for b in &p.patched_bytes {
                        let _ = write!(bytes, "\\x{b:02X}");
                    }
                    let _ = writeln!(
                        out,
                        "  {{ 0x{:X}, \"{}\", {} }},",
                        p.address,
                        bytes,
                        p.patched_bytes.len()
                    );
                }
                out.push_str("};\n");
                out
            }
            _ => {
                use std::fmt::Write as _;
                let mut out = format!("; {} patches\n", applied.len());
                for p in &applied {
                    let patched_hex: String = p
                        .patched_bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let _ = writeln!(out, "{:#010X}: {}", p.address, patched_hex);
                }
                out
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn format_timestamp(ts: u64) -> String {
    format!("t+{}s", ts % 100_000)
}

fn generate_demo_patches() -> Vec<Patch> {
    vec![
        Patch {
            id: 1,
            address: 0x0040_1234,
            original_bytes: vec![0x75, 0x10],
            patched_bytes: vec![0xEB, 0x10],
            size: 2,
            description: "Bypass license check - turn conditional jump into unconditional".into(),
            status: PatchStatus::Applied,
            source: PatchSource::Manual,
            applied_at: unix_now() - 120,
            tags: vec!["license".into(), "bypass".into()],
        },
        Patch {
            id: 2,
            address: 0x0040_50A0,
            original_bytes: vec![0xFF, 0x15, 0x80, 0x20, 0x40, 0x00],
            patched_bytes: vec![0x33, 0xC0, 0x90, 0x90, 0x90, 0x90],
            size: 6,
            description: "NOP out IsDebuggerPresent call, force return 0".into(),
            status: PatchStatus::Applied,
            source: PatchSource::Script,
            applied_at: unix_now() - 60,
            tags: vec!["anti-debug".into()],
        },
        Patch {
            id: 3,
            address: 0x0040_6780,
            original_bytes: vec![0x8B, 0x45, 0xFC, 0x85, 0xC0, 0x74, 0x20],
            patched_bytes: vec![0x8B, 0x45, 0xFC, 0x85, 0xC0, 0x90, 0x90],
            size: 7,
            description: "Remove null pointer check in handler".into(),
            status: PatchStatus::Pending,
            source: PatchSource::Manual,
            applied_at: unix_now(),
            tags: vec![],
        },
        Patch {
            id: 4,
            address: 0x0040_7B20,
            original_bytes: vec![0xE8, 0xDE, 0xAD, 0x00, 0x00],
            patched_bytes: vec![0x90, 0x90, 0x90, 0x90, 0x90],
            size: 5,
            description: "NOP out telemetry upload call".into(),
            status: PatchStatus::Reverted,
            source: PatchSource::Imported,
            applied_at: unix_now() - 300,
            tags: vec!["telemetry".into()],
        },
        Patch {
            id: 5,
            address: 0x0040_8000,
            original_bytes: vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10],
            patched_bytes: vec![0xC3, 0x8B, 0xEC, 0x83, 0xEC, 0x10],
            size: 6,
            description: "Stub out validation function (force early return)".into(),
            status: PatchStatus::VerifyFailed,
            source: PatchSource::Debugger,
            applied_at: unix_now() - 600,
            tags: vec!["validation".into()],
        },
    ]
}

// ---------------------------------------------------------------------------
// Per-UIState slot
// ---------------------------------------------------------------------------

/// Panel-local state that lives inside the global `UIState`. Owns the
/// `PatchesPanel` so the renderer can clone it out fresh each frame.
#[derive(Debug, Clone, Default)]
pub struct PatchesPanelExtState {
    pub panel: PatchesPanel,
}

// ---------------------------------------------------------------------------
// Render — entry point, follows the overview.rs panel convention.
// ---------------------------------------------------------------------------

pub fn render_patches_panel_ext(
    state: Arc<Mutex<UIState>>,
    data: &AppData,
) -> impl IntoElement + '_ {
    // Caller holds the UI mutex; parking_lot is not reentrant so we don't
    // re-lock here. Drop the Arc and build the per-panel state fresh, merging
    // any live applied patches from AppData.
    drop(state);
    let panel = {
        let mut p = PatchesPanel::default();
        merge_live_patches(&mut p, data);
        p
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(render_toolbar(&panel))
        .child(render_summary_bar(&panel))
        .child(div().flex_1().overflow_hidden().child(match panel.active_view {
            ActiveView::PatchList => render_patch_list(&panel).into_any_element(),
            ActiveView::AddPatch => render_add_patch_view(&panel).into_any_element(),
            ActiveView::Preview => render_preview_view(&panel).into_any_element(),
            ActiveView::UndoHistory => render_undo_history_view(&panel).into_any_element(),
        }))
        .child(if panel.show_export_dialog {
            render_export_dialog(&panel).into_any_element()
        } else {
            div().into_any_element()
        })
        .child(if panel.show_import_dialog {
            render_import_dialog(&panel).into_any_element()
        } else {
            div().into_any_element()
        })
}

/// Merge live `AppData::patches` into the panel as `Applied` entries.
/// This is the sole source of patch data in production — the legacy demo
/// seed has been removed from `PatchesPanel::default()`.
fn merge_live_patches(panel: &mut PatchesPanel, data: &AppData) {
    for (i, lp) in data.patches.iter().enumerate() {
        panel.patches.push(Patch {
            id: 1_000 + i as u64,
            address: lp.addr.0,
            original_bytes: lp.original.clone(),
            patched_bytes: lp.patched.clone(),
            size: lp.patched.len().max(lp.original.len()),
            description: lp.comment.clone(),
            status: PatchStatus::Applied,
            source: PatchSource::Imported,
            applied_at: unix_now(),
            tags: vec![],
        });
    }
}

// ---------------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------------

fn render_toolbar(panel: &PatchesPanel) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::TOOLBAR_H))
        .px_2()
        .gap_1()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(tb_btn_primary("+ Add Patch"))
        .child(tb_btn("Apply All"))
        .child(tb_btn("Revert All"))
        .child(tb_btn("Apply Sel"))
        .child(tb_btn("Revert Sel"))
        .child(divider())
        .child(tb_btn("Import"))
        .child(tb_btn("Export"))
        .child(divider())
        .child(view_btn("List", panel.active_view == ActiveView::PatchList))
        .child(view_btn("Preview", panel.active_view == ActiveView::Preview))
        .child(view_btn(
            "Undo History",
            panel.active_view == ActiveView::UndoHistory,
        ))
        .child(divider())
        .child(tb_btn(if panel.is_verifying {
            "Verifying..."
        } else {
            "Verify"
        }))
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(format!(
                    "Filter: {}",
                    if panel.filter_text.is_empty() {
                        "(none)"
                    } else {
                        panel.filter_text.as_str()
                    }
                ))
                .truncate(),
        )
        .child(
            div()
                .px_2()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(match &panel.filter_status {
                    None => "Status: All".to_string(),
                    Some(s) => format!("Status: {}", s.label()),
                })
                .truncate(),
        )
}

fn render_summary_bar(panel: &PatchesPanel) -> impl IntoElement {
    let applied = panel
        .patches
        .iter()
        .filter(|p| p.status == PatchStatus::Applied)
        .count();
    let pending = panel
        .patches
        .iter()
        .filter(|p| p.status == PatchStatus::Pending)
        .count();
    let failed = panel
        .patches
        .iter()
        .filter(|p| p.status == PatchStatus::VerifyFailed)
        .count();
    let total = panel.patches.len();

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_3()
        .h(px(22.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(stat_text(&format!("{total} patches"), colors::text_primary()))
        .child(stat_text(&format!("{applied} applied"), colors::ok()))
        .child(stat_text(&format!("{pending} pending"), colors::warn()))
        .child(if failed > 0 {
            stat_text(&format!("{failed} MISMATCH"), colors::err()).into_any_element()
        } else {
            div().into_any_element()
        })
        .child(div().flex_1())
        .child(stat_text(
            &format!(
                "history: {}/{}",
                panel.current_history_idx + 1,
                panel.undo_history.len()
            ),
            colors::text_muted(),
        ))
}

fn stat_text(s: &str, color: Hsla) -> impl IntoElement {
    div()
        .text_size(px(sizes::LABEL))
        .text_color(color)
        .child(s.to_string())
        .truncate()
}

// ---------------------------------------------------------------------------
// Patch list view
// ---------------------------------------------------------------------------

fn render_patch_list(panel: &PatchesPanel) -> impl IntoElement {
    let filter_lower = panel.filter_text.to_lowercase();
    let mut filtered: Vec<usize> = (0..panel.patches.len())
        .filter(|&i| {
            let p = &panel.patches[i];
            if let Some(ref st) = panel.filter_status {
                if &p.status != st {
                    return false;
                }
            }
            if !filter_lower.is_empty() {
                let addr_str = format!("{:#018X}", p.address).to_lowercase();
                if !addr_str.contains(&filter_lower)
                    && !p.description.to_lowercase().contains(&filter_lower)
                {
                    return false;
                }
            }
            true
        })
        .collect();

    if panel.sort_by_address {
        filtered.sort_by_key(|&i| panel.patches[i].address);
    }

    let rows: Vec<_> = filtered
        .iter()
        .map(|&idx| {
            let is_sel = panel.selected_idx == Some(idx);
            render_patch_row(&panel.patches[idx], is_sel)
        })
        .collect();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .child(render_list_header())
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .children(rows),
        )
        .child(if let Some(idx) = panel.selected_idx {
            if idx < panel.patches.len() {
                render_patch_detail(&panel.patches[idx]).into_any_element()
            } else {
                div().into_any_element()
            }
        } else {
            div().into_any_element()
        })
}

fn render_list_header() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(20.0))
        .px_2()
        .gap_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(div().w(px(6.0)))
        .child(hdr_cell("Address", 140.0))
        .child(hdr_cell("Orig", 110.0))
        .child(hdr_cell("Patched", 110.0))
        .child(hdr_cell("Sz", 36.0))
        .child(hdr_cell("Status", 70.0))
        .child(hdr_cell("Source", 70.0))
        .child(hdr_cell("Tags", 110.0))
        .child(hdr_flex("Description"))
        .child(hdr_cell("When", 70.0))
}

fn hdr_cell(label: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn hdr_flex(label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(label)
        .truncate()
}

fn render_patch_row(patch: &Patch, selected: bool) -> impl IntoElement {
    let orig_hex: String = patch
        .original_bytes
        .iter()
        .take(6)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let patched_hex: String = patch
        .patched_bytes
        .iter()
        .take(6)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let tags = patch.tags.join(", ");

    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H + 4.0))
        .px_2()
        .gap_2()
        .bg(if patch.status == PatchStatus::VerifyFailed {
            Hsla {
                h: 348.0 / 360.0,
                s: 0.5,
                l: 0.10,
                a: 0.6,
            }
        } else if selected {
            colors::bg_selection()
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .border_b_1()
        .border_color(colors::border())
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        // Status bar
        .child(
            div()
                .w(px(6.0))
                .h(px(sizes::ROW_H + 2.0))
                .bg(patch.status.color())
                .rounded_sm(),
        )
        .child(
            div()
                .w(px(140.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_address())
                .child(format!("{:#018X}", patch.address))
                .truncate(),
        )
        .child(
            div()
                .w(px(110.0))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::err())
                .overflow_hidden()
                .child(orig_hex)
                .truncate(),
        )
        .child(
            div()
                .w(px(110.0))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::ok())
                .overflow_hidden()
                .child(patched_hex)
                .truncate(),
        )
        .child(
            div()
                .w(px(36.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child(format!("{}b", patch.size))
                .truncate(),
        )
        .child(
            div()
                .w(px(70.0))
                .text_size(px(sizes::LABEL))
                .text_color(patch.status.color())
                .child(patch.status.label())
                .truncate(),
        )
        .child(
            div()
                .w(px(70.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(patch.source.label())
                .truncate(),
        )
        .child(
            div()
                .w(px(110.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::syn_symbol())
                .overflow_hidden()
                .child(tags)
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .overflow_hidden()
                .child(patch.description.clone())
                .truncate(),
        )
        .child(
            div()
                .w(px(70.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child(format_timestamp(patch.applied_at))
                .truncate(),
        )
}

fn render_patch_detail(patch: &Patch) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .py_2()
        .bg(colors::bg_surface())
        .border_t_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .child(kv("Address", &format!("{:#018X}", patch.address)))
                .child(kv("Size", &format!("{} bytes", patch.size)))
                .child(kv("Status", patch.status.label()))
                .child(kv("Source", patch.source.label()))
                .child(kv("Applied", &format_timestamp(patch.applied_at))),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(patch.description.clone())
                .truncate(),
        )
        .child(render_hex_diff_inline(patch))
}

fn kv(k: &str, v: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_1()
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child(format!("{k}:"))
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .child(v.to_string())
                .truncate(),
        )
}

fn render_hex_diff_inline(patch: &Patch) -> impl IntoElement {
    let diffs = patch.byte_diff();
    let row_len = 16usize;

    div()
        .flex()
        .flex_col()
        .gap_px()
        .children(diffs.chunks(row_len).map(|chunk| {
            let offset = chunk[0].offset;
            let mut row = div().flex().flex_row().items_center().gap_2().child(
                div()
                    .w(px(60.0))
                    .text_size(px(sizes::LABEL - 1.0))
                    .text_color(colors::text_muted())
                    .child(format!("{offset:04X}:")),
            );

            let mut orig_row = div().flex().flex_row().gap_px();
            for d in chunk {
                let (txt, col) = match d.original {
                    Some(b) if d.changed => (format!("{b:02X}"), colors::err()),
                    Some(b) => (format!("{b:02X}"), colors::text_secondary()),
                    None => ("..".into(), colors::text_muted()),
                };
                orig_row = orig_row.child(
                    div()
                        .w(px(18.0))
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(col)
                        .child(txt),
                );
            }
            row = row.child(orig_row);
            row = row.child(
                div()
                    .px_1()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .child("->"),
            );
            let mut new_row = div().flex().flex_row().gap_px();
            for d in chunk {
                let (txt, col) = match d.patched {
                    Some(b) if d.changed => (format!("{b:02X}"), colors::ok()),
                    Some(b) => (format!("{b:02X}"), colors::text_secondary()),
                    None => ("..".into(), colors::text_muted()),
                };
                new_row = new_row.child(
                    div()
                        .w(px(18.0))
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(col)
                        .child(txt),
                );
            }
            row = row.child(new_row);
            row
        }))
}

// ---------------------------------------------------------------------------
// Add patch view
// ---------------------------------------------------------------------------

fn render_add_patch_view(panel: &PatchesPanel) -> impl IntoElement {
    let f = &panel.add_form;

    let preview = if !f.patched_hex.is_empty() || !f.original_hex.is_empty() {
        if let (Some(orig), Some(patched)) = (
            AddPatchForm::parse_hex_bytes(&f.original_hex),
            AddPatchForm::parse_hex_bytes(&f.patched_hex),
        ) {
            let p = Patch {
                id: 0,
                address: f.parse_address().unwrap_or(0),
                original_bytes: orig.clone(),
                patched_bytes: patched.clone(),
                size: orig.len().max(patched.len()),
                description: String::new(),
                status: PatchStatus::Pending,
                source: PatchSource::Manual,
                applied_at: 0,
                tags: vec![],
            };
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child("Preview:")
                        .truncate(),
                )
                .child(render_hex_diff_inline(&p))
                .into_any_element()
        } else {
            div().into_any_element()
        }
    } else {
        div().into_any_element()
    };

    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Add Patch Manually")
                .truncate(),
        )
        .child(form_row("Address (hex)", &f.address_str, "0x00401234"))
        .child(form_row("Original bytes", &f.original_hex, "75 10 90"))
        .child(form_row("Patched bytes", &f.patched_hex, "EB 10 90"))
        .child(form_row("Description", &f.description, "Why this patch?"))
        .child(preview)
        .child(if let Some(err) = &f.error {
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::err())
                .child(format!("Error: {err}"))
                .truncate()
                .into_any_element()
        } else {
            div().into_any_element()
        })
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(tb_btn_primary("Add Patch"))
                .child(tb_btn("Cancel")),
        )
}

fn form_row(label: &str, value: &str, hint: &str) -> impl IntoElement {
    let display = if value.is_empty() { hint } else { value };
    let color = if value.is_empty() {
        colors::text_muted()
    } else {
        colors::text_primary()
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(140.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(format!("{label}:"))
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .px_2()
                .py_1()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .text_size(px(sizes::LABEL))
                .text_color(color)
                .child(display.to_string())
                .truncate(),
        )
}

// ---------------------------------------------------------------------------
// Preview view
// ---------------------------------------------------------------------------

fn render_preview_view(panel: &PatchesPanel) -> impl IntoElement {
    let Some(idx) = panel.selected_idx else {
        return div()
            .flex()
            .items_center()
            .justify_center()
            .h_full()
            .child(
                div()
                    .text_size(px(sizes::LABEL))
                    .text_color(colors::text_muted())
                    .child("No patch selected")
                    .truncate(),
            )
            .into_any_element();
    };
    if idx >= panel.patches.len() {
        return div().into_any_element();
    }

    let patch = &panel.patches[idx];

    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child(format!("Patch Preview - {:#018X}", patch.address))
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(patch.description.clone())
                .truncate(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .child(legend_chip("orig", colors::err()))
                .child(legend_chip("patched", colors::ok()))
                .child(legend_chip("unchanged", colors::text_muted())),
        )
        .child(render_hex_diff_inline(patch))
        .into_any_element()
}

fn legend_chip(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .child(div().w_3().h_3().rounded_sm().bg(color))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(label.to_string())
                .truncate(),
        )
}

// ---------------------------------------------------------------------------
// Undo history view
// ---------------------------------------------------------------------------

fn render_undo_history_view(panel: &PatchesPanel) -> impl IntoElement {
    let current = panel.current_history_idx;
    let entries: Vec<_> = panel
        .undo_history
        .iter()
        .enumerate()
        .rev()
        .map(|(i, snap)| render_history_entry(snap, i, i == current))
        .collect();

    div()
        .flex()
        .flex_col()
        .gap_1()
        .p_3()
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Undo History")
                .truncate(),
        )
        .children(entries)
}

fn render_history_entry(snap: &HistorySnapshot, _idx: usize, current: bool) -> impl IntoElement {
    let applied = snap
        .patch_states
        .iter()
        .filter(|(_, s)| *s == PatchStatus::Applied)
        .count();

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_2()
        .py_1()
        .bg(if current {
            colors::bg_selection()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if current {
            colors::border_focus()
        } else {
            colors::border()
        })
        .rounded_sm()
        .child(
            div()
                .w(px(10.0))
                .text_size(px(sizes::LABEL))
                .text_color(if current { colors::ok() } else { colors::text_muted() })
                .child(if current { "*" } else { "o" })
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child(snap.label.clone())
                .truncate(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child(format!(" - t+{}s", snap.timestamp % 10_000))
                .truncate(),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child(format!("{applied} patches applied"))
                .truncate(),
        )
        .child(if !current {
            tb_btn("Restore").into_any_element()
        } else {
            div().into_any_element()
        })
}

// ---------------------------------------------------------------------------
// Export / Import dialogs
// ---------------------------------------------------------------------------

fn render_export_dialog(panel: &PatchesPanel) -> impl IntoElement {
    let formats = [
        ExportFormat::BinaryPatch,
        ExportFormat::PythonPatcher,
        ExportFormat::CHexArray,
        ExportFormat::IdaPatchFormat,
        ExportFormat::Xdelta,
    ];
    let preview = panel.generate_export_preview();

    overlay_card("Export Patches")
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .children(formats.iter().map(|f| {
                    let active = f == &panel.export_format;
                    radio_row(f.label(), active)
                })),
        )
        .child(form_row("Output path", &panel.export_path, "patches.out"))
        .child(
            div()
                .max_h(px(140.0))
                .overflow_hidden()
                .p_2()
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_secondary())
                .child(preview)
                .truncate(),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(tb_btn_primary("Export"))
                .child(tb_btn("Close")),
        )
}

fn render_import_dialog(panel: &PatchesPanel) -> impl IntoElement {
    let formats = [
        ImportFormat::CustomPatch,
        ImportFormat::IdaPatchFormat,
        ImportFormat::Xdelta,
    ];
    overlay_card("Import Patches")
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .children(formats.iter().map(|f| {
                    let active = f == &panel.import_format;
                    radio_row(f.label(), active)
                })),
        )
        .child(form_row("File path", &panel.import_path, "patches.in"))
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(tb_btn_primary("Import"))
                .child(tb_btn("Close")),
        )
}

fn overlay_card(
    title: &str,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .bg(colors::bg_surface())
        .border_1()
        .border_color(colors::border_accent())
        .rounded_md()
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::accent())
                .font_weight(FontWeight::SEMIBOLD)
                .child(title.to_string())
                .truncate(),
        )
}

fn radio_row(label: &str, active: bool) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(10.0))
                .h(px(10.0))
                .rounded_full()
                .border_1()
                .border_color(if active {
                    colors::accent()
                } else {
                    colors::border()
                })
                .bg(if active {
                    colors::accent()
                } else {
                    Hsla {
                        h: 0.0,
                        s: 0.0,
                        l: 0.0,
                        a: 0.0,
                    }
                }),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(if active {
                    colors::text_primary()
                } else {
                    colors::text_secondary()
                })
                .child(label.to_string())
                .truncate(),
        )
}

// ---------------------------------------------------------------------------
// Small shared chrome
// ---------------------------------------------------------------------------

fn tb_btn(label: &'static str) -> impl IntoElement {
    div()
        .px_2()
        .h(px(22.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(colors::text_secondary())
        .text_size(px(sizes::LABEL))
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label)
}

fn tb_btn_primary(label: &'static str) -> impl IntoElement {
    div()
        .px_2()
        .h(px(22.0))
        .bg(colors::accent())
        .border_1()
        .border_color(colors::accent())
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.05,
            a: 1.0,
        })
        .text_size(px(sizes::LABEL))
        .hover(|s| s.bg(colors::accent_hover()))
        .child(label)
}

fn view_btn(label: &'static str, active: bool) -> impl IntoElement {
    div()
        .px_2()
        .h(px(22.0))
        .bg(if active {
            colors::bg_active()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if active {
            colors::border_focus()
        } else {
            colors::border()
        })
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(if active {
            colors::text_bright()
        } else {
            colors::text_secondary()
        })
        .text_size(px(sizes::LABEL))
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label)
}

fn divider() -> impl IntoElement {
    div().w(px(1.0)).h(px(20.0)).bg(colors::border())
}

// ---------------------------------------------------------------------------
// ensure-used (mirrors the convention in patches.rs / overview.rs)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn ensure_used_patches_panel() {
    // Status / source / formats — touch every variant.
    for s in [
        PatchStatus::Applied,
        PatchStatus::Reverted,
        PatchStatus::Pending,
        PatchStatus::VerifyFailed,
    ] {
        let _ = s.label();
        let _ = s.color();
    }
    for s in [
        PatchSource::Manual,
        PatchSource::Imported,
        PatchSource::Script,
        PatchSource::Debugger,
    ] {
        let _ = s.label();
    }
    for f in [
        ExportFormat::BinaryPatch,
        ExportFormat::PythonPatcher,
        ExportFormat::CHexArray,
        ExportFormat::IdaPatchFormat,
        ExportFormat::Xdelta,
    ] {
        let _ = f.label();
    }
    for f in [
        ImportFormat::CustomPatch,
        ImportFormat::IdaPatchFormat,
        ImportFormat::Xdelta,
    ] {
        let _ = f.label();
    }
    for v in [
        ActiveView::PatchList,
        ActiveView::AddPatch,
        ActiveView::Preview,
        ActiveView::UndoHistory,
    ] {
        let _ = matches!(v, ActiveView::PatchList);
    }

    // AddPatchForm — exercise parsers/validator.
    let mut form = AddPatchForm::default();
    form.address_str = "0x401000".into();
    form.original_hex = "75 10".into();
    form.patched_hex = "EB 10".into();
    form.description = "x".into();
    let _ = form.parse_address();
    let _ = AddPatchForm::parse_hex_bytes("00 11");
    let _ = form.validate();
    form.error = Some("e".into());
    let _ = &form.error;

    // Patch + ByteDiff
    let patch = Patch {
        id: 1,
        address: 0,
        original_bytes: vec![0x90],
        patched_bytes: vec![0xCC],
        size: 1,
        description: "x".into(),
        status: PatchStatus::Applied,
        source: PatchSource::Manual,
        applied_at: 0,
        tags: vec!["t".into()],
    };
    let diffs = patch.byte_diff();
    for d in &diffs {
        let _ = (d.offset, d.original, d.patched, d.changed);
    }

    // HistorySnapshot
    let snap = HistorySnapshot {
        timestamp: 0,
        label: "x".into(),
        patch_states: vec![(1, PatchStatus::Applied)],
    };
    let _ = (&snap.timestamp, &snap.label, &snap.patch_states);

    // PatchesPanel — touch every public mutator + queries.
    let mut panel = PatchesPanel::new();
    let _ = panel.take_navigate_address();
    panel.navigate_to_address = Some(0);
    let _ = panel.take_navigate_address();
    panel.apply_all();
    panel.revert_all();
    panel.apply_selected(&[0]);
    panel.revert_selected(&[0]);
    panel.verify_patches();
    panel.push_history("x");
    panel.restore_snapshot(0);
    panel.export_format = ExportFormat::PythonPatcher;
    let _ = panel.generate_export_preview();
    panel.export_format = ExportFormat::CHexArray;
    let _ = panel.generate_export_preview();
    panel.export_format = ExportFormat::BinaryPatch;
    let _ = panel.generate_export_preview();
    panel.show_export_dialog = true;
    panel.show_import_dialog = true;
    panel.export_path = "out".into();
    panel.import_path = "in".into();
    panel.import_format = ImportFormat::Xdelta;
    panel.is_verifying = false;
    panel.verify_results = vec![(1, true)];
    panel.next_id += 1;
    panel.selected_idxs.push(0);
    panel.filter_text = "x".into();
    panel.filter_status = Some(PatchStatus::Applied);
    panel.sort_by_address = true;
    panel.add_form = AddPatchForm::default();
    panel.current_history_idx = 0;
    let _ = (&panel.patches, &panel.selected_idx, &panel.selected_idxs);

    // PatchesPanelExtState
    let ext = PatchesPanelExtState::default();
    let _ = &ext.panel;

    // Top-level render fn and every internal builder.
    let st: Arc<Mutex<UIState>> = Arc::new(Mutex::new(UIState::default()));
    let data = AppData::default();
    let _ = render_patches_panel_ext(Arc::clone(&st), &data);

    let _ = render_toolbar(&panel);
    let _ = render_summary_bar(&panel);
    let _ = render_patch_list(&panel);
    let _ = render_list_header();
    let _ = hdr_cell("x", 10.0);
    let _ = hdr_flex("x");
    let _ = render_patch_row(&patch, false);
    let _ = render_patch_row(&patch, true);
    let _ = render_patch_detail(&patch);
    let _ = kv("k", "v");
    let _ = render_hex_diff_inline(&patch);
    let _ = render_add_patch_view(&panel);
    let _ = form_row("k", "v", "h");
    panel.active_view = ActiveView::Preview;
    panel.selected_idx = Some(0);
    let _ = render_preview_view(&panel);
    let _ = legend_chip("l", colors::ok());
    let _ = render_undo_history_view(&panel);
    let _ = render_history_entry(&snap, 0, true);
    let _ = render_history_entry(&snap, 0, false);
    let _ = render_export_dialog(&panel);
    let _ = render_import_dialog(&panel);
    let _ = overlay_card("t");
    let _ = radio_row("l", true);
    let _ = radio_row("l", false);
    let _ = tb_btn("x");
    let _ = tb_btn_primary("x");
    let _ = view_btn("x", true);
    let _ = view_btn("x", false);
    let _ = divider();
    let _ = stat_text("x", colors::ok());
    let _ = format_timestamp(123);
    let _ = unix_now();
    let _ = generate_demo_patches();
    let mut p2 = PatchesPanel::default();
    merge_live_patches(&mut p2, &data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_roundtrip() {
        assert_eq!(
            AddPatchForm::parse_hex_bytes("75 10 EB").unwrap(),
            vec![0x75, 0x10, 0xEB]
        );
        assert!(AddPatchForm::parse_hex_bytes("XYZ").is_none());
        assert!(AddPatchForm::parse_hex_bytes("ABC").is_none()); // odd len
    }

    #[test]
    fn parse_address_accepts_prefix() {
        let mut f = AddPatchForm::default();
        f.address_str = "0x401234".into();
        assert_eq!(f.parse_address(), Some(0x40_1234));
        f.address_str = "DEADBEEF".into();
        assert_eq!(f.parse_address(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn byte_diff_lengths() {
        let p = Patch {
            id: 0,
            address: 0,
            original_bytes: vec![1, 2, 3],
            patched_bytes: vec![1, 2, 4, 5],
            size: 4,
            description: String::new(),
            status: PatchStatus::Pending,
            source: PatchSource::Manual,
            applied_at: 0,
            tags: vec![],
        };
        let d = p.byte_diff();
        assert_eq!(d.len(), 4);
        assert!(d[2].changed);
        assert!(d[3].changed);
    }

    #[test]
    fn apply_revert_cycle() {
        let mut panel = PatchesPanel::new();
        panel.patches = generate_demo_patches();
        panel.apply_all();
        assert!(panel
            .patches
            .iter()
            .all(|p| p.status != PatchStatus::Pending));
        panel.revert_all();
        assert!(panel
            .patches
            .iter()
            .filter(|p| p.status == PatchStatus::Applied)
            .count()
            <= 1);
    }

    #[test]
    fn export_preview_python_contains_seek() {
        let mut panel = PatchesPanel::new();
        panel.patches = generate_demo_patches();
        panel.export_format = ExportFormat::PythonPatcher;
        let s = panel.generate_export_preview();
        assert!(s.contains("f.seek"));
    }

    #[test]
    fn history_push_and_restore() {
        let mut panel = PatchesPanel::new();
        let start = panel.current_history_idx;
        panel.push_history("step");
        assert_eq!(panel.current_history_idx, start + 1);
        panel.restore_snapshot(start);
        assert_eq!(panel.current_history_idx, start);
    }
}
