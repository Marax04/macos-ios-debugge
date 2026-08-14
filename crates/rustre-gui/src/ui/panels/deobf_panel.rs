// ============================================================================
// ui/panels/deobf_panel.rs — Deobfuscation / code-simplification panel.
//
// Surfaces the public entry points of the `rustre-deobf*` family of crates:
//   - rustre-deobf           : pipeline, pass registry, reports
//   - rustre-deobf-antianti  : anti-analysis detection / patching
//   - rustre-deobf-cff       : control-flow flattening recovery
//   - rustre-deobf-mba       : mixed bool/arith simplification
//   - rustre-deobf-opaque    : opaque-predicate elimination
//   - rustre-deobf-smc       : self-modifying code unpacker
//   - rustre-deobf-string    : encoded string recovery
//   - rustre-deobf-vm        : VM-protected handler analysis
//   - rustre-deobf-vmlift    : VM bytecode -> LLIL lifting
//
// The panel is presented as a left sub-tree of crates with the 3-7 most
// prominent entry points per crate listed on the right with a short
// description and an "Invoke" affordance. State follows the same convention
// as `yara_panel`: defaults are built per-frame and `ensure_used_deobf` wires
// every public symbol so dead-code lints stay clean.
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use gpui::{div, hsla, Hsla, InteractiveElement, IntoElement, ParentElement, Styled};
use parking_lot::Mutex;
use std::sync::Arc;

// ── Data types ───────────────────────────────────────────────────────────────

/// A single backend entry point exposed in the UI.
#[derive(Debug, Clone)]
pub struct DeobfEntry {
    pub symbol: &'static str,
    pub kind: EntryKind,
    pub summary: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Function,
    Type,
    Pass,
    Pipeline,
    Report,
}

impl EntryKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Function => "fn",
            Self::Type => "type",
            Self::Pass => "pass",
            Self::Pipeline => "pipeline",
            Self::Report => "report",
        }
    }
    pub fn color(self) -> Hsla {
        match self {
            Self::Function => hsla(150.0 / 360.0, 0.45, 0.62, 1.0),
            Self::Type => hsla(45.0 / 360.0, 0.70, 0.60, 1.0),
            Self::Pass => hsla(258.0 / 360.0, 0.55, 0.72, 1.0),
            Self::Pipeline => hsla(200.0 / 360.0, 0.65, 0.70, 1.0),
            Self::Report => hsla(20.0 / 360.0, 0.55, 0.62, 1.0),
        }
    }
}

/// A backend crate grouping a small set of entry points.
#[derive(Debug, Clone)]
pub struct DeobfCrate {
    pub crate_name: &'static str,
    pub blurb: &'static str,
    pub entries: Vec<DeobfEntry>,
}

/// Status of the most recent invocation. Lives in `AppData::deobf_status`;
/// the panel mirrors it into its own state at render time. The `Idle` variant
/// is the natural "no work has been run" state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InvocationStatus {
    #[default]
    Idle,
    Running,
    Ok(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct DeobfPanelState {
    pub crates: Vec<DeobfCrate>,
    pub selected_crate_idx: usize,
    pub selected_entry_idx: Option<usize>,
    pub status: InvocationStatus,
    pub filter: String,
    pub show_report: bool,
}

impl Default for DeobfPanelState {
    fn default() -> Self {
        Self {
            crates: catalog(),
            selected_crate_idx: 0,
            selected_entry_idx: Some(0),
            status: InvocationStatus::Idle,
            filter: String::new(),
            show_report: false,
        }
    }
}

impl DeobfPanelState {
    /// Build the panel view-model from live `AppData`. The catalog is the
    /// static surface of public entry points exposed by the `rustre-deobf*`
    /// crate family (this is intentional metadata, not runtime data — it
    /// describes the API a user can invoke). The *status* and *report*
    /// reflect the most recent pipeline run, both of which live in `AppData`
    /// and are populated by `analysis/engine.rs` when a pipeline completes.
    pub fn from_app_data(data: &AppData) -> Self {
        Self {
            crates: catalog(),
            selected_crate_idx: 0,
            selected_entry_idx: Some(0),
            status: data.deobf_status.clone(),
            filter: String::new(),
            show_report: !data.deobf_report.is_empty(),
        }
    }
}

impl DeobfPanelState {
    /// Mark the currently-selected entry as having been "invoked". This is the
    /// hook UI controllers (menus, toolbar buttons, context menus) call when
    /// the user requests the operation; downstream wiring will replace the
    /// simulated status update with a real backend call.
    pub fn invoke_selected(&mut self) {
        let Some(idx) = self.selected_entry_idx else {
            self.status = InvocationStatus::Failed("no entry selected".into());
            return;
        };
        let Some(c) = self.crates.get(self.selected_crate_idx) else {
            self.status = InvocationStatus::Failed("invalid crate".into());
            return;
        };
        let Some(e) = c.entries.get(idx) else {
            self.status = InvocationStatus::Failed("invalid entry".into());
            return;
        };
        self.status = InvocationStatus::Ok(format!("queued {}::{}", c.crate_name, e.symbol));
    }

    pub fn select_crate(&mut self, i: usize) {
        if i < self.crates.len() {
            self.selected_crate_idx = i;
            self.selected_entry_idx = if self.crates[i].entries.is_empty() {
                None
            } else {
                Some(0)
            };
        }
    }

    pub fn select_entry(&mut self, i: usize) {
        if let Some(c) = self.crates.get(self.selected_crate_idx) {
            if i < c.entries.len() {
                self.selected_entry_idx = Some(i);
            }
        }
    }

    pub fn toggle_report(&mut self) {
        self.show_report = !self.show_report;
    }

    pub fn clear_status(&mut self) {
        self.status = InvocationStatus::Idle;
    }
}

// ── Catalog: the 3-7 highest-value entry points per crate ──────────────────

fn catalog() -> Vec<DeobfCrate> {
    vec![
        DeobfCrate {
            crate_name: "rustre-deobf",
            blurb: "Core deobfuscation pipeline framework.",
            entries: vec![
                DeobfEntry {
                    symbol: "DeobfPipeline",
                    kind: EntryKind::Pipeline,
                    summary: "Compose and run a sequence of deobfuscation passes.",
                },
                DeobfEntry {
                    symbol: "PassRegistry",
                    kind: EntryKind::Type,
                    summary: "Look up and instantiate registered passes by name.",
                },
                DeobfEntry {
                    symbol: "DeobfReport",
                    kind: EntryKind::Report,
                    summary: "Aggregate pass results into a structured report.",
                },
                DeobfEntry {
                    symbol: "XorDecryptor",
                    kind: EntryKind::Type,
                    summary: "Single-byte and small-key XOR string decoder.",
                },
                DeobfEntry {
                    symbol: "Base64Decoder",
                    kind: EntryKind::Type,
                    summary: "Detect and decode embedded base64 blobs.",
                },
                DeobfEntry {
                    symbol: "ChaCha20Decryptor",
                    kind: EntryKind::Type,
                    summary: "Recover ChaCha20-encrypted strings given key+nonce.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-antianti",
            blurb: "Detect and neutralise anti-analysis tricks.",
            entries: vec![
                DeobfEntry {
                    symbol: "AntiAntiPass",
                    kind: EntryKind::Pass,
                    summary: "Run the full anti-analysis neutralisation pass.",
                },
                DeobfEntry {
                    symbol: "AntiDebugDetector",
                    kind: EntryKind::Type,
                    summary: "Locate IsDebuggerPresent / PEB / NtQuery checks.",
                },
                DeobfEntry {
                    symbol: "AntiVmDetector",
                    kind: EntryKind::Type,
                    summary: "Find CPUID / VMware artefact probes.",
                },
                DeobfEntry {
                    symbol: "signature_database",
                    kind: EntryKind::Function,
                    summary: "Built-in technique signatures (debug / VM / sandbox).",
                },
                DeobfEntry {
                    symbol: "generate_frida_script",
                    kind: EntryKind::Function,
                    summary: "Emit a Frida bypass script for the located hits.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-cff",
            blurb: "Control-flow flattening recovery (OLLVM/Tigress).",
            entries: vec![
                DeobfEntry {
                    symbol: "CffDeobfuscationPass",
                    kind: EntryKind::Pass,
                    summary: "End-to-end CFF detection + recovery pipeline pass.",
                },
                DeobfEntry {
                    symbol: "CffDetector",
                    kind: EntryKind::Type,
                    summary: "Detect flattening candidates in a function.",
                },
                DeobfEntry {
                    symbol: "CffRecoverer",
                    kind: EntryKind::Type,
                    summary: "Reconstruct the original CFG from a flat dispatcher.",
                },
                DeobfEntry {
                    symbol: "CffDispatcherDetector",
                    kind: EntryKind::Type,
                    summary: "Identify the dispatcher block and state variable.",
                },
                DeobfEntry {
                    symbol: "CffDeflattener",
                    kind: EntryKind::Type,
                    summary: "Rewrite a flattened function into structured form.",
                },
                DeobfEntry {
                    symbol: "CffVerifier",
                    kind: EntryKind::Type,
                    summary: "Sanity-check recovered CFG against original semantics.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-mba",
            blurb: "Mixed boolean/arithmetic expression simplification.",
            entries: vec![
                DeobfEntry {
                    symbol: "MbaDeobfuscationPass",
                    kind: EntryKind::Pass,
                    summary: "Run the full MBA simplification pass.",
                },
                DeobfEntry {
                    symbol: "MbaSimplifier",
                    kind: EntryKind::Type,
                    summary: "Pattern-driven rewriter using the rule database.",
                },
                DeobfEntry {
                    symbol: "SiMBASimplifier",
                    kind: EntryKind::Type,
                    summary: "SiMBA linear-MBA solver (truth-table based).",
                },
                DeobfEntry {
                    symbol: "LinearMbaDetector",
                    kind: EntryKind::Type,
                    summary: "Find linear-MBA shaped expressions in IL.",
                },
                DeobfEntry {
                    symbol: "build_rule_database",
                    kind: EntryKind::Function,
                    summary: "Load the built-in identity / rewrite rules.",
                },
                DeobfEntry {
                    symbol: "normalize_expression",
                    kind: EntryKind::Function,
                    summary: "Canonicalise a text MBA expression.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-opaque",
            blurb: "Opaque predicate detection and elimination.",
            entries: vec![
                DeobfEntry {
                    symbol: "OpaqueDeobfPass",
                    kind: EntryKind::Pass,
                    summary: "Detect and remove opaque branches end-to-end.",
                },
                DeobfEntry {
                    symbol: "OpaqueDetector",
                    kind: EntryKind::Type,
                    summary: "Locate candidate opaque branches in a CFG.",
                },
                DeobfEntry {
                    symbol: "OpaqueEliminator",
                    kind: EntryKind::Type,
                    summary: "Patch out branches proven constant.",
                },
                DeobfEntry {
                    symbol: "ConstantPropagator",
                    kind: EntryKind::Type,
                    summary: "Cheap intra-block constant propagation.",
                },
                DeobfEntry {
                    symbol: "MbaOpaqueDetector",
                    kind: EntryKind::Type,
                    summary: "Detect MBA-shaped opaque predicates.",
                },
                DeobfEntry {
                    symbol: "build_known_patterns",
                    kind: EntryKind::Function,
                    summary: "Load the curated opaque-predicate pattern library.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-smc",
            blurb: "Self-modifying / packed code analysis.",
            entries: vec![
                DeobfEntry {
                    symbol: "SmcPass",
                    kind: EntryKind::Pass,
                    summary: "Top-level SMC detection + reconstruction pass.",
                },
                DeobfEntry {
                    symbol: "SmcDetector",
                    kind: EntryKind::Type,
                    summary: "Heuristic detector for write-then-execute regions.",
                },
                DeobfEntry {
                    symbol: "SmcDecryptor",
                    kind: EntryKind::Type,
                    summary: "Apply a recovered key over an encrypted region.",
                },
                DeobfEntry {
                    symbol: "DynamicSmcReconstructor",
                    kind: EntryKind::Type,
                    summary: "Replay write events to reconstruct unpacked code.",
                },
                DeobfEntry {
                    symbol: "UnpackedRegionDetector",
                    kind: EntryKind::Type,
                    summary: "Identify finalised unpacked regions for analysis.",
                },
                DeobfEntry {
                    symbol: "shannon_entropy",
                    kind: EntryKind::Function,
                    summary: "Per-region entropy heuristic.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-string",
            blurb: "Encoded / encrypted / stack string recovery.",
            entries: vec![
                DeobfEntry {
                    symbol: "xor_brute_force_top3",
                    kind: EntryKind::Function,
                    summary: "Return the three best single-byte XOR candidates.",
                },
                DeobfEntry {
                    symbol: "recover_multibyte_xor",
                    kind: EntryKind::Function,
                    summary: "Recover multi-byte XOR keys via IC analysis.",
                },
                DeobfEntry {
                    symbol: "detect_rc4_ksa_in_mlil",
                    kind: EntryKind::Function,
                    summary: "Find RC4 key-schedule patterns in MLIL.",
                },
                DeobfEntry {
                    symbol: "detect_base64_variant",
                    kind: EntryKind::Function,
                    summary: "Identify standard / urlsafe / custom base64 alphabets.",
                },
                DeobfEntry {
                    symbol: "detect_mlil_stack_strings",
                    kind: EntryKind::Function,
                    summary: "Reconstruct stack-built strings from MLIL.",
                },
                DeobfEntry {
                    symbol: "caesar_brute_force",
                    kind: EntryKind::Function,
                    summary: "Brute-force all 25 Caesar shifts and score.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-vm",
            blurb: "VM-protected handler analysis (VMProtect, Themida).",
            entries: vec![
                DeobfEntry {
                    symbol: "VmDetector",
                    kind: EntryKind::Type,
                    summary: "Whole-binary heuristic VM-protection detector.",
                },
                DeobfEntry {
                    symbol: "VmDispatcherDetector",
                    kind: EntryKind::Type,
                    summary: "Locate the bytecode dispatcher loop.",
                },
                DeobfEntry {
                    symbol: "VmLifter",
                    kind: EntryKind::Type,
                    summary: "Lift identified handlers to semantic ops.",
                },
                DeobfEntry {
                    symbol: "VmBytecodeExtractor",
                    kind: EntryKind::Type,
                    summary: "Pull the VM bytecode stream out of the binary.",
                },
                DeobfEntry {
                    symbol: "HandlerClusterer",
                    kind: EntryKind::Type,
                    summary: "Cluster equivalent handlers under semantic ops.",
                },
                DeobfEntry {
                    symbol: "VmProtectorDetector",
                    kind: EntryKind::Type,
                    summary: "Identify the specific protector family.",
                },
            ],
        },
        DeobfCrate {
            crate_name: "rustre-deobf-vmlift",
            blurb: "VM bytecode -> LLIL lifting pipeline.",
            entries: vec![
                DeobfEntry {
                    symbol: "VmLifterPipeline",
                    kind: EntryKind::Pipeline,
                    summary: "Run the whole detect-decode-lift pipeline.",
                },
                DeobfEntry {
                    symbol: "VmLifter",
                    kind: EntryKind::Type,
                    summary: "Lift a single guest instruction to LLIL.",
                },
                DeobfEntry {
                    symbol: "VmDispatcherDetector",
                    kind: EntryKind::Type,
                    summary: "Find raw dispatcher sites in the host code.",
                },
                DeobfEntry {
                    symbol: "VmBytecodeDisassembler",
                    kind: EntryKind::Type,
                    summary: "Disassemble guest bytecode against a recovered ISA.",
                },
                DeobfEntry {
                    symbol: "suggest_mnemonic",
                    kind: EntryKind::Function,
                    summary: "Suggest a printable mnemonic for a handler semantic.",
                },
                DeobfEntry {
                    symbol: "VmLiftReport",
                    kind: EntryKind::Report,
                    summary: "Structured report of the lifting run.",
                },
            ],
        },
    ]
}

// ── Text helpers ────────────────────────────────────────────────────────────

fn text_xs(s: &str, color: Hsla) -> impl IntoElement {
    div().text_xs().text_color(color).truncate().child(s.to_string())
}
fn text_sm(s: &str, color: Hsla) -> impl IntoElement {
    div().text_sm().text_color(color).truncate().child(s.to_string())
}
fn text_md(s: &str, color: Hsla) -> impl IntoElement {
    div().text_base().text_color(color).truncate().child(s.to_string())
}
fn mono_xs(s: &str, color: Hsla) -> impl IntoElement {
    div().text_xs().text_color(color).truncate().child(s.to_string())
}

// ── Render entry-point ──────────────────────────────────────────────────────

pub fn render_deobf_panel(
    state: Arc<Mutex<UIState>>,
    data: &AppData,
) -> impl IntoElement + 'static {
    // Caller in app.rs holds the UI mutex while rendering; parking_lot is not
    // reentrant so we must not re-lock here. Drop the Arc handle and proceed.
    drop(state);

    let st = DeobfPanelState::from_app_data(data);
    let report = data.deobf_report.clone();
    render_with_state_and_report(&st, &report)
}

fn render_with_state(st: &DeobfPanelState) -> impl IntoElement + 'static {
    render_with_state_and_report(st, "")
}

fn render_with_state_and_report(st: &DeobfPanelState, report: &str) -> impl IntoElement + 'static {
    let bg = hsla(230.0 / 360.0, 0.26, 0.07, 1.0);
    let report_owned = report.to_owned();
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(bg)
        .child(render_toolbar(st))
        .child(
            div()
                .flex()
                .flex_row()
                .flex_1()
                .overflow_hidden()
                .child(render_crate_list(st))
                .child(render_detail_with_report(st, &report_owned)),
        )
}

fn render_toolbar(st: &DeobfPanelState) -> impl IntoElement {
    let status_node = match &st.status {
        InvocationStatus::Idle => text_xs("Idle", hsla(0.0, 0.0, 0.55, 1.0)).into_any_element(),
        InvocationStatus::Running => {
            text_xs("Running...", hsla(45.0 / 360.0, 0.75, 0.55, 1.0)).into_any_element()
        }
        InvocationStatus::Ok(m) => text_xs(
            &format!("OK: {m}"),
            hsla(140.0 / 360.0, 0.65, 0.55, 1.0),
        )
        .into_any_element(),
        InvocationStatus::Failed(e) => {
            text_xs(&format!("FAIL: {e}"), hsla(0.0, 0.75, 0.60, 1.0)).into_any_element()
        }
    };

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .py_2()
        .bg(hsla(230.0 / 360.0, 0.24, 0.09, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .child(toolbar_button("Invoke", hsla(140.0 / 360.0, 0.65, 0.50, 1.0)))
        .child(div().w_px().h_6().bg(hsla(0.0, 0.0, 0.20, 1.0)))
        .child(toolbar_button("Run Pipeline", hsla(0.0, 0.0, 0.80, 1.0)))
        .child(toolbar_button("Toggle Report", hsla(0.0, 0.0, 0.80, 1.0)))
        .child(toolbar_button("Clear Status", hsla(0.0, 0.0, 0.80, 1.0)))
        .child(div().flex_1())
        .child(status_node)
        .child(div().w_px().h_6().bg(hsla(0.0, 0.0, 0.20, 1.0)))
        .child(text_xs(
            &format!(
                "{} crates / {} entries",
                st.crates.len(),
                st.crates.iter().map(|c| c.entries.len()).sum::<usize>()
            ),
            hsla(0.0, 0.0, 0.50, 1.0),
        ))
}

fn toolbar_button(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .px_2()
        .py_1()
        .cursor_pointer()
        .rounded_sm()
        .bg(hsla(0.0, 0.0, 0.15, 1.0))
        .border_1()
        .border_color(hsla(0.0, 0.0, 0.25, 1.0))
        .hover(|s| s.bg(hsla(0.0, 0.0, 0.20, 1.0)))
        .child(text_xs(label, color))
}

fn render_crate_list(st: &DeobfPanelState) -> impl IntoElement {
    let filter_lower = st.filter.to_lowercase();
    let rows = st.crates.iter().enumerate().map(|(i, c)| {
        let active = i == st.selected_crate_idx;
        let bg = if active {
            hsla(225.0 / 360.0, 0.65, 0.30, 0.45)
        } else {
            hsla(0.0, 0.0, 0.0, 0.0)
        };
        let visible =
            filter_lower.is_empty() || c.crate_name.to_lowercase().contains(&filter_lower);
        let opacity_color = if visible {
            hsla(0.0, 0.0, 0.85, 1.0)
        } else {
            hsla(0.0, 0.0, 0.40, 1.0)
        };
        div()
            .flex()
            .flex_col()
            .gap_px()
            .px_2()
            .py_1()
            .bg(bg)
            .cursor_pointer()
            .hover(|s| s.bg(hsla(258.0 / 360.0, 0.60, 0.40, 0.20)))
            .child(text_sm(c.crate_name, opacity_color))
            .child(text_xs(c.blurb, hsla(0.0, 0.0, 0.50, 1.0)))
            .child(text_xs(
                &format!("{} entries", c.entries.len()),
                hsla(258.0 / 360.0, 0.45, 0.65, 1.0),
            ))
    });

    div()
        .flex()
        .flex_col()
        .w_64()
        .flex_shrink_0()
        .h_full()
        .border_r_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .bg(hsla(230.0 / 360.0, 0.24, 0.08, 1.0))
        .overflow_hidden()
        .child(
            div()
                .px_2()
                .py_2()
                .border_b_1()
                .border_color(hsla(0.0, 0.0, 0.20, 1.0))
                .child(text_sm("Deobf Crates", hsla(0.0, 0.0, 0.85, 1.0))),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .children(rows.map(IntoElement::into_any_element)),
        )
}

fn render_detail(st: &DeobfPanelState) -> impl IntoElement {
    render_detail_with_report(st, "")
}

fn render_detail_with_report(st: &DeobfPanelState, report: &str) -> impl IntoElement {
    let Some(c) = st.crates.get(st.selected_crate_idx) else {
        return div()
            .flex()
            .items_center()
            .justify_center()
            .flex_1()
            .child(text_sm("No crate selected", hsla(0.0, 0.0, 0.45, 1.0)))
            .into_any_element();
    };

    let entries = c.entries.iter().enumerate().map(|(i, e)| {
        let active = st.selected_entry_idx == Some(i);
        let bg = if active {
            hsla(225.0 / 360.0, 0.55, 0.28, 0.50)
        } else {
            hsla(0.0, 0.0, 0.10, 1.0)
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .p_2()
            .rounded_sm()
            .bg(bg)
            .cursor_pointer()
            .hover(|s| s.bg(hsla(258.0 / 360.0, 0.60, 0.40, 0.18)))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(mono_xs(e.symbol, hsla(45.0 / 360.0, 0.70, 0.65, 1.0)))
                    .child(text_xs(e.kind.label(), e.kind.color()))
                    .child(div().flex_1())
                    .child(toolbar_button("Invoke", hsla(0.0, 0.0, 0.80, 1.0))),
            )
            .child(text_xs(e.summary, hsla(0.0, 0.0, 0.70, 1.0)))
    });

    let mut root = div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .flex_1()
        .overflow_hidden()
        .child(text_md(c.crate_name, hsla(0.0, 0.0, 0.92, 1.0)))
        .child(text_xs(c.blurb, hsla(0.0, 0.0, 0.65, 1.0)))
        .child(section_header("Entry points"))
        .children(entries.map(IntoElement::into_any_element));

    if st.show_report {
        let body = if report.is_empty() {
            "No passes have been run in this session.".to_owned()
        } else {
            report.to_owned()
        };
        root = root.child(section_header("Report (preview)")).child(
            div()
                .px_2()
                .py_1()
                .bg(hsla(0.0, 0.0, 0.10, 1.0))
                .child(mono_xs(&body, hsla(0.0, 0.0, 0.65, 1.0))),
        );
    }

    root.into_any_element()
}

fn section_header(label: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .pb_1()
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.22, 1.0))
        .child(text_sm(label, hsla(258.0 / 360.0, 0.50, 0.68, 1.0)))
}

// ── ensure-used ─────────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_deobf() {
    for k in [
        EntryKind::Function,
        EntryKind::Type,
        EntryKind::Pass,
        EntryKind::Pipeline,
        EntryKind::Report,
    ] {
        let _ = k.label();
        let _ = k.color();
    }

    let mut st = DeobfPanelState::default();
    st.select_crate(1);
    st.select_entry(0);
    st.invoke_selected();
    st.toggle_report();
    st.clear_status();
    let _ = &st.crates;
    let _ = st.selected_crate_idx;
    let _ = st.selected_entry_idx;
    let _ = &st.status;
    let _ = &st.filter;
    let _ = st.show_report;

    for v in [
        InvocationStatus::Idle,
        InvocationStatus::Running,
        InvocationStatus::Ok("x".into()),
        InvocationStatus::Failed("x".into()),
    ] {
        let _ = matches!(v, InvocationStatus::Idle);
    }

    let e = DeobfEntry {
        symbol: "x",
        kind: EntryKind::Function,
        summary: "s",
    };
    let _ = (e.symbol, e.kind, e.summary);

    let c = DeobfCrate {
        crate_name: "n",
        blurb: "b",
        entries: vec![e],
    };
    let _ = (c.crate_name, c.blurb, &c.entries);

    let ui = Arc::new(Mutex::new(UIState::default()));
    let data = AppData::new();
    let _ = render_deobf_panel(Arc::clone(&ui), &data);
    let _ = render_with_state(&st);
    let _ = render_toolbar(&st);
    let _ = render_crate_list(&st);
    let _ = render_detail(&st);
    let _ = section_header("h");
    let _ = toolbar_button("b", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = text_xs("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = text_sm("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = text_md("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = mono_xs("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = catalog();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_populated() {
        let st = DeobfPanelState::default();
        assert!(!st.crates.is_empty());
        assert_eq!(st.crates.len(), 9);
        for c in &st.crates {
            assert!(!c.entries.is_empty());
            assert!(c.entries.len() <= 7);
            assert!(c.entries.len() >= 3);
        }
    }

    #[test]
    fn invoke_changes_status() {
        let mut st = DeobfPanelState::default();
        st.invoke_selected();
        assert!(matches!(st.status, InvocationStatus::Ok(_)));
        st.clear_status();
        assert_eq!(st.status, InvocationStatus::Idle);
    }
}
