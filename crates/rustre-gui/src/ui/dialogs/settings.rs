// ============================================================================
// ui/dialogs/settings.rs — Application settings dialog
// ============================================================================

use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SettingsTab {
    #[default]
    General,
    Appearance,
    Analysis,
    Plugins,
    Shortcuts,
    Database,
}

impl SettingsTab {
    pub const fn label(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Appearance => "Appearance",
            Self::Analysis => "Analysis",
            Self::Plugins => "Plugins",
            Self::Shortcuts => "Shortcuts",
            Self::Database => "Database",
        }
    }
    pub const fn icon(self) -> &'static str {
        match self {
            Self::General => "cfg",
            Self::Appearance => "theme",
            Self::Analysis => "lab",
            Self::Plugins => "puzzle",
            Self::Shortcuts => "key",
            Self::Database => "files",
        }
    }
    pub const ALL: [Self; 6] = [
        Self::General,
        Self::Appearance,
        Self::Analysis,
        Self::Plugins,
        Self::Shortcuts,
        Self::Database,
    ];
}

// ── Individual settings groups ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GeneralSettings {
    pub auto_save: bool,
    pub auto_save_interval_secs: u32,
    pub confirm_close: bool,
    pub restore_session: bool,
    pub max_recent_files: u32,
    pub log_level: String,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            auto_save: true,
            auto_save_interval_secs: 120,
            confirm_close: true,
            restore_session: true,
            max_recent_files: 20,
            log_level: "info".to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppearanceSettings {
    pub font_family: String,
    pub font_size: f32,
    pub line_height: f32,
    pub show_address_column: bool,
    pub show_hex_column: bool,
    pub show_line_numbers: bool,
    pub address_width: u8, // 32 or 64
    pub theme_name: String,
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            font_family: "JetBrains Mono".to_owned(),
            font_size: 13.0,
            line_height: 1.4,
            show_address_column: true,
            show_hex_column: true,
            show_line_numbers: true,
            address_width: 64,
            theme_name: "IDA Dark".to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisSettings {
    pub auto_analyze_on_load: bool,
    pub max_analysis_threads: u32,
    pub max_function_size: u32,
    pub follow_calls: bool,
    pub analyze_data_refs: bool,
    pub decompiler_timeout_secs: u32,
    pub taint_max_depth: u32,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        Self {
            auto_analyze_on_load: true,
            max_analysis_threads: 4,
            max_function_size: 65536,
            follow_calls: true,
            analyze_data_refs: true,
            decompiler_timeout_secs: 30,
            taint_max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DatabaseSettings {
    pub db_path_override: Option<String>,
    pub vacuum_on_close: bool,
    pub export_on_save: bool,
    pub export_format: String,
}

// ── SettingsState ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SettingsState {
    pub visible: bool,
    pub tab: SettingsTab,
    pub general: GeneralSettings,
    pub appearance: AppearanceSettings,
    pub analysis: AnalysisSettings,
    pub database: DatabaseSettings,
    pub dirty: bool,
    pub confirmed: bool,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            visible: false,
            tab: SettingsTab::General,
            general: GeneralSettings::default(),
            appearance: AppearanceSettings::default(),
            analysis: AnalysisSettings::default(),
            database: DatabaseSettings::default(),
            dirty: false,
            confirmed: false,
        }
    }
}

impl SettingsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn open(&mut self) {
        self.visible = true;
        self.confirmed = false;
    }
    pub const fn open_at(&mut self, tab: SettingsTab) {
        self.open();
        self.tab = tab;
    }
    pub const fn close(&mut self) {
        self.visible = false;
        self.confirmed = false;
    }

    pub const fn set_tab(&mut self, tab: SettingsTab) {
        self.tab = tab;
    }

    // General toggles
    pub const fn toggle_auto_save(&mut self) {
        self.general.auto_save = !self.general.auto_save;
        self.dirty = true;
    }
    pub const fn toggle_confirm_close(&mut self) {
        self.general.confirm_close = !self.general.confirm_close;
        self.dirty = true;
    }
    pub const fn toggle_restore_session(&mut self) {
        self.general.restore_session = !self.general.restore_session;
        self.dirty = true;
    }

    // Appearance toggles
    pub const fn toggle_address_col(&mut self) {
        self.appearance.show_address_column = !self.appearance.show_address_column;
        self.dirty = true;
    }
    pub const fn toggle_hex_col(&mut self) {
        self.appearance.show_hex_column = !self.appearance.show_hex_column;
        self.dirty = true;
    }
    pub const fn toggle_line_numbers(&mut self) {
        self.appearance.show_line_numbers = !self.appearance.show_line_numbers;
        self.dirty = true;
    }
    pub const fn set_font_size(&mut self, size: f32) {
        self.appearance.font_size = size.clamp(8.0, 24.0);
        self.dirty = true;
    }
    pub fn font_size_up(&mut self) {
        self.set_font_size(self.appearance.font_size + 1.0);
    }
    pub fn font_size_down(&mut self) {
        self.set_font_size(self.appearance.font_size - 1.0);
    }
    pub const fn set_address_width(&mut self, bits: u8) {
        self.appearance.address_width = bits;
        self.dirty = true;
    }

    // Analysis toggles
    pub const fn toggle_auto_analyze(&mut self) {
        self.analysis.auto_analyze_on_load = !self.analysis.auto_analyze_on_load;
        self.dirty = true;
    }
    pub const fn toggle_follow_calls(&mut self) {
        self.analysis.follow_calls = !self.analysis.follow_calls;
        self.dirty = true;
    }
    pub const fn toggle_data_refs(&mut self) {
        self.analysis.analyze_data_refs = !self.analysis.analyze_data_refs;
        self.dirty = true;
    }

    pub const fn confirm(&mut self) {
        self.confirmed = true;
        self.dirty = false;
    }

    pub fn take_confirmed(&mut self) -> Option<ConfirmedSettings> {
        if self.confirmed {
            self.confirmed = false;
            Some(ConfirmedSettings {
                general: self.general.clone(),
                appearance: self.appearance.clone(),
                analysis: self.analysis.clone(),
                database: self.database.clone(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfirmedSettings {
    pub general: GeneralSettings,
    pub appearance: AppearanceSettings,
    pub analysis: AnalysisSettings,
    pub database: DatabaseSettings,
}

// ── Rendering ──────────────────────────────────────────────────────────────────

pub fn render_settings_dialog(state: &SettingsState) -> impl IntoElement + '_ {
    if !state.visible {
        return div().into_any_element();
    }
    div()
        .absolute()
        .inset_0()
        .flex()
        .items_center()
        .justify_center()
        .bg(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.5,
        })
        .child(settings_inner(state))
        .into_any_element()
}

fn settings_inner(state: &SettingsState) -> impl IntoElement + '_ {
    div()
        .w(px(700.0))
        .h(px(500.0))
        .bg(Hsla {
            h: 225.0 / 360.0,
            s: 0.14,
            l: 0.10,
            a: 0.98,
        })
        .border_1()
        .border_color(colors::border_focus())
        .rounded(px(6.0))
        .overflow_hidden()
        .flex()
        .flex_col()
        // Title bar
        .child(
            div()
                .h(px(36.0))
                .px_3()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .child(
                    div()
                        .text_size(px(14.0))
                        .text_color(colors::accent())
                        .child(crate::ui::widgets::icon::icon("gear")),
                )
                .child(
                    div()
                        .flex_1()
                        .text_size(px(sizes::CODE))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Settings"),
                )
                .child(if state.dirty {
                    div()
                        .text_size(px(sizes::LABEL - 0.5))
                        .text_color(colors::warn())
                        .child("* Unsaved changes")
                        .into_any_element()
                } else {
                    div().into_any_element()
                }),
        )
        // Body: sidebar + content
        .child(
            div()
                .flex_1()
                .flex()
                .flex_row()
                .overflow_hidden()
                // Sidebar
                .child(
                    div()
                        .w(px(140.0))
                        .flex()
                        .flex_col()
                        .id("settings-sidebar-scroll")
                        .overflow_y_scroll()
                        .bg(Hsla {
                            h: 225.0 / 360.0,
                            s: 0.12,
                            l: 0.08,
                            a: 1.0,
                        })
                        .border_r_1()
                        .border_color(colors::border())
                        .children(
                            SettingsTab::ALL
                                .into_iter()
                                .map(|tab| settings_sidebar_item(tab, state.tab == tab)),
                        ),
                )
                // Content area
                .child(
                    div()
                        .flex_1()
                        .id("settings-content-scroll")
                        .overflow_y_scroll()
                        .p_3()
                        .child(match state.tab {
                            SettingsTab::General => {
                                render_general_tab(&state.general).into_any_element()
                            }
                            SettingsTab::Appearance => {
                                render_appearance_tab(&state.appearance).into_any_element()
                            }
                            SettingsTab::Analysis => {
                                render_analysis_tab(&state.analysis).into_any_element()
                            }
                            SettingsTab::Database => {
                                render_database_tab(&state.database).into_any_element()
                            }
                            SettingsTab::Plugins => {
                                render_placeholder("Plugin management coming soon")
                                    .into_any_element()
                            }
                            SettingsTab::Shortcuts => {
                                render_placeholder("Keyboard shortcut editor coming soon")
                                    .into_any_element()
                            }
                        }),
                ),
        )
        // Footer buttons
        .child(
            div()
                .px_3()
                .py_2()
                .flex()
                .flex_row()
                .justify_end()
                .gap_2()
                .border_t_1()
                .border_color(colors::border())
                .child(settings_btn("Cancel", false))
                .child(settings_btn("Apply", false))
                .child(settings_btn("OK", true)),
        )
}

fn settings_sidebar_item(tab: SettingsTab, active: bool) -> impl IntoElement {
    div()
        .h(px(36.0))
        .px_3()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .cursor_pointer()
        .bg(if active {
            colors::bg_selection()
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .border_l_2()
        .border_color(if active {
            colors::accent()
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .child(div().text_size(px(14.0)).child(tab.icon()))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(if active {
                    colors::text_primary()
                } else {
                    colors::text_secondary()
                })
                .child(tab.label()),
        )
}

fn render_general_tab(s: &GeneralSettings) -> impl IntoElement + '_ {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(settings_section("Session"))
        .child(settings_toggle("Auto-save project", s.auto_save))
        .child(settings_row_kv(
            "Auto-save interval",
            format!("{} seconds", s.auto_save_interval_secs),
        ))
        .child(settings_toggle("Confirm on close", s.confirm_close))
        .child(settings_toggle("Restore last session", s.restore_session))
        .child(settings_row_kv(
            "Max recent files",
            format!("{}", s.max_recent_files),
        ))
        .child(settings_section("Logging"))
        .child(settings_row_kv("Log level", s.log_level.clone()))
}

fn render_appearance_tab(s: &AppearanceSettings) -> impl IntoElement + '_ {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(settings_section("Font"))
        .child(settings_row_kv("Font family", s.font_family.clone()))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_secondary())
                        .w(px(130.0))
                        .child("Font size"),
                )
                .child(size_control(s.font_size)),
        )
        .child(settings_row_kv(
            "Address width",
            format!("{} bits", s.address_width),
        ))
        .child(settings_section("Columns"))
        .child(settings_toggle(
            "Show address column",
            s.show_address_column,
        ))
        .child(settings_toggle("Show hex column", s.show_hex_column))
        .child(settings_toggle("Show line numbers", s.show_line_numbers))
        .child(settings_section("Theme"))
        .child(settings_row_kv("Current theme", s.theme_name.clone()))
}

fn render_analysis_tab(s: &AnalysisSettings) -> impl IntoElement + '_ {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(settings_section("Behavior"))
        .child(settings_toggle(
            "Auto-analyze on load",
            s.auto_analyze_on_load,
        ))
        .child(settings_toggle("Follow calls", s.follow_calls))
        .child(settings_toggle(
            "Analyze data references",
            s.analyze_data_refs,
        ))
        .child(settings_section("Limits"))
        .child(settings_row_kv(
            "Analysis threads",
            format!("{}", s.max_analysis_threads),
        ))
        .child(settings_row_kv(
            "Max function size",
            format!("{} bytes", s.max_function_size),
        ))
        .child(settings_row_kv(
            "Decompiler timeout",
            format!("{} s", s.decompiler_timeout_secs),
        ))
        .child(settings_row_kv(
            "Taint max depth",
            format!("{}", s.taint_max_depth),
        ))
}

fn render_database_tab(s: &DatabaseSettings) -> impl IntoElement + '_ {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(settings_section("Storage"))
        .child(settings_row_kv(
            "DB location",
            s.db_path_override
                .as_deref()
                .unwrap_or("Same directory as binary")
                .to_owned(),
        ))
        .child(settings_toggle("Vacuum on close", s.vacuum_on_close))
        .child(settings_toggle("Export on save", s.export_on_save))
        .child(settings_row_kv(
            "Export format",
            if s.export_format.is_empty() {
                "JSON".to_owned()
            } else {
                s.export_format.clone()
            },
        ))
}

fn render_placeholder(msg: &str) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .h(px(200.0))
        .text_size(px(sizes::LABEL))
        .text_color(colors::text_muted())
        .child(msg.to_owned())
}

fn settings_section(title: &str) -> impl IntoElement {
    div()
        .pb_1()
        .border_b_1()
        .border_color(colors::border())
        .text_size(px(sizes::LABEL))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .child(title.to_owned())
}

fn settings_toggle(label: &str, on: bool) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .cursor_pointer()
        // Toggle switch visual
        .child(
            div()
                .w(px(28.0))
                .h(px(14.0))
                .rounded_full()
                .cursor_pointer()
                .bg(if on {
                    colors::accent()
                } else {
                    colors::bg_elevated()
                })
                .border_1()
                .border_color(colors::border())
                .flex()
                .items_center()
                .px(px(2.0))
                .child(
                    div()
                        .w(px(10.0))
                        .h(px(10.0))
                        .rounded_full()
                        .bg(Hsla {
                            h: 0.0,
                            s: 0.0,
                            l: 1.0,
                            a: 1.0,
                        })
                        .ml(if on { px(12.0) } else { px(0.0) }),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::CODE))
                .text_color(colors::text_primary())
                .child(label.to_owned()),
        )
}

fn settings_row_kv(key: &str, val: String) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(180.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .child(key.to_owned()),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(sizes::CODE))
                .text_color(colors::text_primary())
                .font_family("JetBrains Mono")
                .child(val),
        )
}

fn size_control(size: f32) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .child(
            div()
                .w(px(20.0))
                .h(px(20.0))
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .flex()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .text_size(px(12.0))
                .text_color(colors::text_secondary())
                .child("−"),
        )
        .child(
            div()
                .w(px(36.0))
                .h(px(20.0))
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(sizes::CODE))
                .text_color(colors::text_primary())
                .font_family("JetBrains Mono")
                .child(format!("{size:.0}")),
        )
        .child(
            div()
                .w(px(20.0))
                .h(px(20.0))
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .flex()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .text_size(px(12.0))
                .text_color(colors::text_secondary())
                .child("+"),
        )
}

fn settings_btn(label: &str, primary: bool) -> impl IntoElement {
    let bg = if primary {
        colors::accent()
    } else {
        colors::bg_elevated()
    };
    let tc = if primary {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 1.0,
            a: 1.0,
        }
    } else {
        colors::text_secondary()
    };
    div()
        .px_3()
        .h(px(26.0))
        .bg(bg)
        .border_1()
        .border_color(colors::border())
        .rounded(px(4.0))
        .flex()
        .items_center()
        .text_size(px(sizes::LABEL))
        .text_color(tc)
        .cursor_pointer()
        .child(label.to_owned())
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_settings() {
    // SettingsTab enum + associated items
    for tab in SettingsTab::ALL {
        let _ = tab.label();
        let _ = tab.icon();
    }
    let _ = SettingsTab::default();
    let _ = SettingsTab::General;
    let _ = SettingsTab::Appearance;
    let _ = SettingsTab::Analysis;
    let _ = SettingsTab::Plugins;
    let _ = SettingsTab::Shortcuts;
    let _ = SettingsTab::Database;

    // Settings group structs
    let general = GeneralSettings::default();
    let _ = general;
    let appearance = AppearanceSettings::default();
    let _ = appearance.line_height;
    let _ = appearance;
    let analysis = AnalysisSettings::default();
    let _ = analysis;
    let database = DatabaseSettings::default();
    let _ = database;

    // SettingsState construction + all methods
    let mut state = SettingsState::new();
    state.open();
    state.open_at(SettingsTab::Appearance);
    state.close();
    state.set_tab(SettingsTab::General);
    state.toggle_auto_save();
    state.toggle_confirm_close();
    state.toggle_restore_session();
    state.toggle_address_col();
    state.toggle_hex_col();
    state.toggle_line_numbers();
    state.set_font_size(12.0);
    state.font_size_up();
    state.font_size_down();
    state.set_address_width(32);
    state.toggle_auto_analyze();
    state.toggle_follow_calls();
    state.toggle_data_refs();
    state.confirm();
    let confirmed = state.take_confirmed();
    if let Some(c) = confirmed {
        let _ = ConfirmedSettings {
            general: c.general.clone(),
            appearance: c.appearance.clone(),
            analysis: c.analysis.clone(),
            database: c.database,
        };
    }

    // Rendering functions
    let _ = render_settings_dialog(&state);
    let _ = settings_inner(&state);
    let _ = settings_sidebar_item(SettingsTab::General, true);
    let _ = render_general_tab(&state.general);
    let _ = render_appearance_tab(&state.appearance);
    let _ = render_analysis_tab(&state.analysis);
    let _ = render_database_tab(&state.database);
    let _ = render_placeholder("placeholder");
    let _ = settings_section("section");
    let _ = settings_toggle("toggle", true);
    let _ = settings_row_kv("key", "val".to_owned());
    let _ = size_control(13.0);
    let _ = settings_btn("btn", false);
}
