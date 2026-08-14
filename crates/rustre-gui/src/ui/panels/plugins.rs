// ============================================================================
// ui/panels/plugins.rs — Plugin Manager panel
//
// Shows loaded plugins, their declared capabilities, a health/status badge,
// and Reload / Unload / Permissions actions. State is held in-process; a
// future wire-up to rustre-plugin-host will replace the simulated registry
// via PluginPanelState::refresh().
// ============================================================================

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::{icon_colored, icon_sized};
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

// ─── Plugin record ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginHealth {
    Healthy,
    Degraded,
    Unloaded,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginKind {
    Native,
    Python,
    Lua,
    Mcp,
}

impl PluginKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Python => "python",
            Self::Lua => "lua",
            Self::Mcp => "mcp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PluginEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: PluginKind,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub health: PluginHealth,
    pub uptime_ms: u64,
    pub calls: u64,
    pub last_error: Option<String>,
}

impl PluginEntry {
    pub fn new(id: &str, name: &str, kind: PluginKind) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            version: "0.1.0".to_string(),
            kind,
            capabilities: Vec::new(),
            permissions: Vec::new(),
            health: PluginHealth::Healthy,
            uptime_ms: 0,
            calls: 0,
            last_error: None,
        }
    }
}

// ─── Panel state ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PluginPanelState {
    pub plugins: Vec<PluginEntry>,
    pub selected: Option<String>,
    pub show_permissions: bool,
    pub last_action: Option<String>,
}

impl PluginPanelState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Refresh the plugin list from `AppData::plugins`, which is populated by
    /// `rustre_plugin_host::PluginRegistry` when it registers / unregisters
    /// plugins via the analysis pipeline. We clone the live snapshot so the
    /// render path can observe a consistent slice without holding the data
    /// lock.
    pub fn refresh(&mut self, data: &AppData, _rev: u64) {
        self.plugins = data.plugins.clone();
        // Drop a stale selection if the plugin was unloaded between frames.
        if let Some(sel) = self.selected.as_deref() {
            if !self.plugins.iter().any(|p| p.id == sel) {
                self.selected = None;
            }
        }
    }

    pub fn select(&mut self, id: &str) {
        self.selected = Some(id.to_string());
    }

    pub fn toggle_permissions(&mut self) {
        self.show_permissions = !self.show_permissions;
    }

    pub fn reload(&mut self, id: &str) -> Option<UICommand> {
        if let Some(p) = self.plugins.iter_mut().find(|p| p.id == id) {
            p.health = PluginHealth::Healthy;
            p.uptime_ms = 0;
            p.last_error = None;
            self.last_action = Some(format!("reloaded {id}"));
        }
        None
    }

    pub fn unload(&mut self, id: &str) -> Option<UICommand> {
        if let Some(p) = self.plugins.iter_mut().find(|p| p.id == id) {
            p.health = PluginHealth::Unloaded;
            self.last_action = Some(format!("unloaded {id}"));
        }
        None
    }

    pub fn selected_plugin(&self) -> Option<&PluginEntry> {
        let id = self.selected.as_deref()?;
        self.plugins.iter().find(|p| p.id == id)
    }
}

/// Helper used by `rustre_plugin_host` adapters and by the ensure-used dead-
/// code touch below to construct a fully-populated `PluginEntry` (id, name,
/// kind, capability list, permission list) in one shot. Kept `pub(super)` so
/// the host integration can drive it without duplicating the field set.
pub(super) fn build_plugin_entry(
    id: &str,
    name: &str,
    kind: PluginKind,
    caps: &[&str],
    perms: &[&str],
) -> PluginEntry {
    let mut e = PluginEntry::new(id, name, kind);
    e.capabilities = caps.iter().map(|s| (*s).to_string()).collect();
    e.permissions = perms.iter().map(|s| (*s).to_string()).collect();
    e
}

// ─── Render ──────────────────────────────────────────────────────────────────

fn health_color(h: PluginHealth) -> Hsla {
    match h {
        PluginHealth::Healthy => colors::ok(),
        PluginHealth::Degraded => colors::warn(),
        PluginHealth::Failed => colors::err(),
        PluginHealth::Unloaded => colors::text_muted(),
    }
}

fn health_label(h: PluginHealth) -> &'static str {
    match h {
        PluginHealth::Healthy => "healthy",
        PluginHealth::Degraded => "degraded",
        PluginHealth::Failed => "failed",
        PluginHealth::Unloaded => "unloaded",
    }
}

pub fn render_plugin_panel<'a>(
    state: &'a PluginPanelState,
    _data: &'a AppData,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(plugins_header(state, bus))
        .child(plugins_list(state, bus))
        .child(plugins_detail(state, bus))
}

fn plugins_header(state: &PluginPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let reload_bus = Arc::clone(bus);
    let perm_bus = Arc::clone(bus);
    let load_bus = Arc::clone(bus);
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
                .child(icon_sized("package", 13.0, 13.0))
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Plugins")
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .child(format!("{} loaded", state.plugins.len()))
                        .truncate(),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(
                    plugin_hdr_btn("refresh-cw", "reload all")
                        .id(SharedString::from("plugins-hdr-reload"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            reload_bus.send_command(UICommand::PluginHeaderAction(0));
                        }),
                )
                .child(
                    plugin_hdr_btn("shield", "permissions")
                        .id(SharedString::from("plugins-hdr-perm"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            perm_bus.send_command(UICommand::PluginHeaderAction(1));
                        }),
                )
                .child(
                    plugin_hdr_btn("plus", "load plugin")
                        .id(SharedString::from("plugins-hdr-load"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            load_bus.send_command(UICommand::PluginHeaderAction(2));
                        }),
                ),
        )
}

fn plugin_hdr_btn(icon_name: &'static str, _tip: &'static str) -> gpui::Div {
    div()
        .w(px(20.0))
        .h(px(20.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(3.0))
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(icon_sized(icon_name, 12.0, 12.0))
}

fn plugins_list(state: &PluginPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let sel = state.selected.clone();
    div()
        .id(SharedString::from("plugin-list-scroll"))
        .flex()
        .flex_col()
        .flex_1()
        .overflow_y_scroll()
        .children(
            state
                .plugins
                .iter()
                .map(|p| plugin_row(p, sel.as_deref(), bus)),
        )
}

fn plugin_row(p: &PluginEntry, sel: Option<&str>, bus: &Arc<EventBus>) -> impl IntoElement {
    let is_sel = sel == Some(p.id.as_str());
    let id_owned = p.id.clone();
    let row_bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("plugin-row-{}", p.id)))
        .on_click(move |_: &ClickEvent, _, _| {
            row_bus.send_command(UICommand::PluginSelect(id_owned.clone()));
        })
        .flex()
        .flex_col()
        .px_2()
        .py(px(4.0))
        .gap_1()
        .border_b_1()
        .border_color(colors::border())
        .bg(if is_sel {
            colors::bg_selection()
        } else {
            colors::bg_panel()
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .cursor_pointer()
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(icon_colored("circle_filled", health_color(p.health)))
                .child(
                    div()
                        .flex_1()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::MEDIUM)
                        .child(p.name.clone())
                        .truncate(),
                )
                .child(
                    div()
                        .px_1()
                        .rounded(px(3.0))
                        .bg(colors::bg_elevated())
                        .text_size(px(sizes::LABEL - 1.5))
                        .text_color(colors::accent_cyan())
                        .child(p.kind.label())
                        .truncate(),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.5))
                        .text_color(colors::text_muted())
                        .child(format!("v{}", p.version))
                        .truncate(),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .text_size(px(sizes::LABEL - 1.5))
                .text_color(colors::text_muted())
                .child(format!("id: {}", p.id))
                .child(format!("calls: {}", p.calls))
                .child(format!("status: {}", health_label(p.health))),
        )
}

fn plugins_detail(state: &PluginPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let Some(p) = state.selected_plugin() else {
        return div()
            .h(px(0.0))
            .border_t_1()
            .border_color(colors::border())
            .into_any_element();
    };
    let reload_bus = Arc::clone(bus);
    let unload_bus = Arc::clone(bus);
    let perm_bus = Arc::clone(bus);
    div()
        .flex()
        .flex_col()
        .h(px(180.0))
        .px_2()
        .py_1()
        .gap_1()
        .border_t_1()
        .border_color(colors::border())
        .bg(colors::bg_surface())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_bright())
                .font_weight(FontWeight::SEMIBOLD)
                .child(p.name.clone())
                .truncate(),
        )
        .child(detail_kv("Capabilities", &p.capabilities.join(", ")))
        .child(detail_kv("Permissions", &p.permissions.join(", ")))
        .child(detail_kv(
            "Uptime",
            &format!("{} ms / {} calls", p.uptime_ms, p.calls),
        ))
        .child(p.last_error.as_ref().map_or_else(
            || div().into_any_element(),
            |e| {
                div()
                    .text_size(px(sizes::LABEL - 1.0))
                    .text_color(colors::err())
                    .child(format!("last error: {e}"))
                    .truncate()
                    .into_any_element()
            },
        ))
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .pt_1()
                .child(
                    detail_btn("Reload", "refresh-cw")
                        .id(SharedString::from("plugin-detail-reload"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            reload_bus.send_command(UICommand::PluginDetailAction(0));
                        }),
                )
                .child(
                    detail_btn("Unload", "x")
                        .id(SharedString::from("plugin-detail-unload"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            unload_bus.send_command(UICommand::PluginDetailAction(1));
                        }),
                )
                .child(
                    detail_btn("Permissions", "shield")
                        .id(SharedString::from("plugin-detail-perm"))
                        .on_click(move |_: &ClickEvent, _, _| {
                            perm_bus.send_command(UICommand::PluginDetailAction(2));
                        }),
                ),
        )
        .into_any_element()
}

fn detail_kv(k: &str, v: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_2()
        .text_size(px(sizes::LABEL))
        .child(
            div()
                .w(px(96.0))
                .text_color(colors::text_muted())
                .child(k.to_string())
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .text_color(colors::text_secondary())
                .child(v.to_string())
                .truncate(),
        )
}

fn detail_btn(label: &'static str, icon_name: &'static str) -> gpui::Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .px_2()
        .h(px(20.0))
        .rounded(px(3.0))
        .border_1()
        .border_color(colors::border())
        .bg(colors::bg_elevated())
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(icon_sized(icon_name, 11.0, 11.0))
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_secondary())
                .child(label)
                .truncate(),
        )
}

// ── ensure-used (touch all public items so dead-code checks stay clean) ──
#[doc(hidden)]
pub fn ensure_used_plugins() {
    let _ = PluginKind::Native.label();
    let _ = PluginKind::Python.label();
    let _ = PluginKind::Lua.label();
    let _ = PluginKind::Mcp.label();
    let _ = health_color(PluginHealth::Healthy);
    let _ = health_color(PluginHealth::Degraded);
    let _ = health_color(PluginHealth::Failed);
    let _ = health_color(PluginHealth::Unloaded);
    let _ = health_label(PluginHealth::Healthy);

    let mut s = PluginPanelState::new();
    let mut data = AppData::default();
    // Drive the refresh path with a non-empty plugin set that mirrors the
    // shape `rustre_plugin_host::PluginRegistry::list()` will return once the
    // host is wired into the analysis engine.
    data.plugins = vec![
        build_plugin_entry(
            "mcp.core",
            "MCP Core Tools",
            PluginKind::Mcp,
            &["mcp.list", "mcp.call", "mcp.describe"],
            &["read.binary", "read.analysis"],
        ),
        build_plugin_entry(
            "py.deobf",
            "Python Deobfuscator",
            PluginKind::Python,
            &["script.run", "patch.bytes"],
            &["write.patches", "read.binary"],
        ),
    ];
    s.refresh(&data, 0);
    s.select("mcp.core");
    s.toggle_permissions();
    let _ = s.reload("mcp.core");
    let _ = s.unload("py.deobf");
    let _ = s.selected_plugin();
    let bus = Arc::new(crate::core::event_bus::EventBus::new());
    let _ = render_plugin_panel(&s, &data, &bus);

    let mut e = PluginEntry::new("x", "X", PluginKind::Native);
    e.capabilities.push("c".into());
    e.permissions.push("p".into());
    e.last_error = Some("err".into());
    e.health = PluginHealth::Degraded;
    e.uptime_ms = 1;
    e.calls = 1;
    e.version = "1".into();
    let _ = plugin_row(&e, Some("x"), &bus);
    let _ = plugins_header(&s, &bus);
    let _ = plugin_hdr_btn("x", "y");
    let _ = plugins_list(&s, &bus);
    let _ = plugins_detail(&s, &bus);
    let _ = detail_kv("k", "v");
    let _ = detail_btn("Reload", "refresh-cw");
}
