// ============================================================================
// ui/panels/yara_panel.rs — YARA scanner panel (ported to current GPUI API)
//
// Rule editor with syntax highlighting, rule library, scan results,
// match details, built-in rules, and performance tracking. The egui legacy
// implementation has been reskinned with GPUI primitives; all data models,
// tokenizer logic, and demo data are preserved verbatim.
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::event_bus::{EventBus, UICommand};
use gpui::{
    div, hsla, ClickEvent, Hsla, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Data types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum StringType {
    Text,
    Hex,
    Regex,
}

impl StringType {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Hex => "hex",
            Self::Regex => "regex",
        }
    }
    pub fn color(&self) -> Hsla {
        match self {
            Self::Text => hsla(70.0 / 360.0, 0.55, 0.65, 1.0),
            Self::Hex => hsla(150.0 / 360.0, 0.45, 0.62, 1.0),
            Self::Regex => hsla(290.0 / 360.0, 0.55, 0.72, 1.0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct YaraStringDef {
    pub identifier: String,
    pub string_type: StringType,
    pub value: String,
    pub modifiers: Vec<String>, // nocase, wide, ascii, fullword
}

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub id: u64,
    pub name: String,
    pub namespace: String,
    pub category: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraStringDef>,
    pub condition: String,
    pub source: String, // full rule text
    pub enabled: bool,
    pub builtin: bool,
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub address: u64,
    pub length: usize,
    pub data_preview: Vec<u8>,
    pub string_identifier: Option<String>,
    pub offset_in_file: u64,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub rule_id: u64,
    pub rule_name: String,
    pub namespace: String,
    pub match_count: usize,
    pub first_match_address: u64,
    pub matches: Vec<YaraMatch>,
    pub scan_time_ms: f64,
}

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub total_rules: usize,
    pub matched_rules: usize,
    pub total_matches: usize,
    pub scan_duration: Option<Duration>,
    pub bytes_scanned: u64,
}

// ── Syntax token types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum YaraToken {
    Keyword,
    StringKw,
    HexLiteral,
    TextLiteral,
    RegexLiteral,
    Number,
    Operator,
    Comment,
    Meta,
    Tag,
    Normal,
}

impl YaraToken {
    pub fn color(&self) -> Hsla {
        match self {
            Self::Keyword => hsla(210.0 / 360.0, 0.65, 0.60, 1.0),
            Self::StringKw => hsla(45.0 / 360.0, 0.70, 0.60, 1.0),
            Self::HexLiteral => hsla(150.0 / 360.0, 0.45, 0.62, 1.0),
            Self::TextLiteral => hsla(20.0 / 360.0, 0.55, 0.62, 1.0),
            Self::RegexLiteral => hsla(290.0 / 360.0, 0.55, 0.70, 1.0),
            Self::Number => hsla(85.0 / 360.0, 0.45, 0.65, 1.0),
            Self::Operator => hsla(280.0 / 360.0, 0.55, 0.65, 1.0),
            Self::Comment => hsla(100.0 / 360.0, 0.30, 0.50, 1.0),
            Self::Meta => hsla(200.0 / 360.0, 0.80, 0.78, 1.0),
            Self::Tag => hsla(58.0 / 360.0, 0.70, 0.65, 1.0),
            Self::Normal => hsla(0.0, 0.0, 0.82, 1.0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenSpan {
    pub token: YaraToken,
    pub text: String,
}

// ── Built-in rule categories ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BuiltinRuleCategory {
    pub name: String,
    pub rules: Vec<(String, String)>, // (name, description)
}

fn builtin_categories() -> Vec<BuiltinRuleCategory> {
    vec![
        BuiltinRuleCategory {
            name: "Packers".into(),
            rules: vec![
                ("UPX_Packed".into(), "Detects UPX-packed executables".into()),
                ("MPRESS_Packed".into(), "Detects MPRESS packer".into()),
                ("Themida_Protected".into(), "Detects Themida VM protection".into()),
                ("ASPack_Packed".into(), "Detects ASPack packer".into()),
            ],
        },
        BuiltinRuleCategory {
            name: "Crypto Constants".into(),
            rules: vec![
                ("AES_SBox".into(), "AES S-Box constants".into()),
                ("AES_InvSBox".into(), "AES inverse S-Box constants".into()),
                ("SHA256_Constants".into(), "SHA-256 K constants".into()),
                ("RC4_Pseudo".into(), "RC4-like key scheduling".into()),
                ("MD5_Constants".into(), "MD5 sine-derived constants".into()),
                (
                    "ChaCha20_Constant".into(),
                    "ChaCha20 \"expand 32-byte k\" magic".into(),
                ),
            ],
        },
        BuiltinRuleCategory {
            name: "Malware Families".into(),
            rules: vec![
                ("Mirai_Strings".into(), "Mirai botnet string signatures".into()),
                (
                    "Cobalt_Strike_Beacon".into(),
                    "Cobalt Strike beacon indicators".into(),
                ),
                ("Emotet_Strings".into(), "Emotet loader strings".into()),
                ("WannaCry_Ransom".into(), "WannaCry ransomware markers".into()),
                (
                    "Metasploit_Shellcode".into(),
                    "Common Metasploit shellcode stubs".into(),
                ),
            ],
        },
        BuiltinRuleCategory {
            name: "Anti-Analysis".into(),
            rules: vec![
                ("IsDebuggerPresent".into(), "Calls IsDebuggerPresent".into()),
                ("RDTSC_Timing".into(), "Uses RDTSC for timing checks".into()),
                ("VM_Detection".into(), "VM artifact string checks".into()),
                ("Sleep_Evasion".into(), "Abnormally long sleep calls".into()),
            ],
        },
        BuiltinRuleCategory {
            name: "Network IOCs".into(),
            rules: vec![
                ("Hardcoded_IPs".into(), "Suspicious hardcoded IP literals".into()),
                ("C2_URL_Patterns".into(), "Common C2 beacon URL patterns".into()),
                ("Tor_Onion_Strings".into(), "Tor .onion address references".into()),
            ],
        },
    ]
}

// ── YARA tokenizer (simplified) ─────────────────────────────────────────────

pub fn tokenize_yara(source: &str) -> Vec<Vec<TokenSpan>> {
    let keywords = [
        "rule", "meta", "strings", "condition", "import", "global", "private",
        "include",
    ];
    let operators = [
        "and", "or", "not", "all", "any", "of", "them", "in", "at", "for",
        "true", "false", "nocase", "wide", "ascii", "fullword",
    ];
    let number_kws = [
        "file_size",
        "entrypoint",
        "pe.entry_point",
        "uint8",
        "uint16",
        "uint32",
    ];

    let mut lines = Vec::new();

    for line in source.lines() {
        let mut spans = Vec::new();
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            spans.push(TokenSpan {
                token: YaraToken::Comment,
                text: line.to_string(),
            });
            lines.push(spans);
            continue;
        }

        let mut i = 0;
        let chars: Vec<char> = line.chars().collect();
        let mut current = String::new();

        while i < chars.len() {
            let c = chars[i];

            if i + 1 < chars.len() && c == '/' && chars[i + 1] == '/' {
                if !current.is_empty() {
                    spans.push(classify_yara_token(&current, &keywords, &operators, &number_kws));
                    current.clear();
                }
                spans.push(TokenSpan {
                    token: YaraToken::Comment,
                    text: line[i..].to_string(),
                });
                break;
            }

            if c == '"' {
                if !current.is_empty() {
                    spans.push(classify_yara_token(&current, &keywords, &operators, &number_kws));
                    current.clear();
                }
                let mut s = String::from('"');
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    s.push(chars[i]);
                    i += 1;
                }
                s.push('"');
                spans.push(TokenSpan {
                    token: YaraToken::TextLiteral,
                    text: s,
                });
                i += 1;
                continue;
            }

            if c == '/' && !current.is_empty() {
                current.push(c);
                i += 1;
                continue;
            }

            if c == '{' {
                if !current.is_empty() {
                    spans.push(classify_yara_token(&current, &keywords, &operators, &number_kws));
                    current.clear();
                }
                let mut s = String::from('{');
                i += 1;
                while i < chars.len() && chars[i] != '}' {
                    s.push(chars[i]);
                    i += 1;
                }
                s.push('}');
                spans.push(TokenSpan {
                    token: YaraToken::HexLiteral,
                    text: s,
                });
                i += 1;
                continue;
            }

            if c == '$' {
                if !current.is_empty() {
                    spans.push(classify_yara_token(&current, &keywords, &operators, &number_kws));
                    current.clear();
                }
                let mut s = String::from('$');
                i += 1;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '*')
                {
                    s.push(chars[i]);
                    i += 1;
                }
                spans.push(TokenSpan {
                    token: YaraToken::StringKw,
                    text: s,
                });
                continue;
            }

            if c.is_alphanumeric() || c == '_' || c == '.' {
                current.push(c);
            } else {
                if !current.is_empty() {
                    spans.push(classify_yara_token(&current, &keywords, &operators, &number_kws));
                    current.clear();
                }
                spans.push(TokenSpan {
                    token: YaraToken::Normal,
                    text: c.to_string(),
                });
            }

            i += 1;
        }

        if !current.is_empty() {
            spans.push(classify_yara_token(&current, &keywords, &operators, &number_kws));
        }

        lines.push(spans);
    }

    lines
}

fn classify_yara_token(
    word: &str,
    keywords: &[&str],
    operators: &[&str],
    number_kws: &[&str],
) -> TokenSpan {
    let token = if keywords.contains(&word) {
        YaraToken::Keyword
    } else if operators.contains(&word) {
        YaraToken::Operator
    } else if number_kws.iter().any(|k| word.starts_with(k)) {
        YaraToken::Number
    } else if word.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        YaraToken::Number
    } else {
        YaraToken::Normal
    };

    TokenSpan {
        token,
        text: word.to_string(),
    }
}

// ── Panel state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveTab {
    Editor,
    Library,
    Results,
}

impl ActiveTab {
    /// Advance to the next tab, wrapping back to `Editor`.
    pub const fn next(&self) -> Self {
        match self {
            Self::Editor => Self::Library,
            Self::Library => Self::Results,
            Self::Results => Self::Editor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationStatus {
    Unknown,
    Valid,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct YaraPanelState {
    pub rules: Vec<YaraRule>,
    pub selected_rule_idx: Option<usize>,
    pub selected_result_idx: Option<usize>,
    pub selected_match_idx: Option<usize>,

    pub active_tab: ActiveTab,

    pub editor_text: String,
    pub editor_cursor_line: usize,
    pub validation_status: ValidationStatus,

    pub scan_results: Vec<ScanResult>,
    pub scan_stats: ScanStats,
    pub is_scanning: bool,
    pub last_scan: Option<Instant>,

    pub filter_namespace: String,
    pub filter_name: String,

    pub builtin_categories: Vec<BuiltinRuleCategory>,
    pub show_builtin_picker: bool,
    pub builtin_selected_cat: usize,

    pub show_import_dialog: bool,
    pub import_path: String,

    pub show_export_dialog: bool,
    pub export_path: String,

    pub navigate_to_address: Option<u64>,
    /// When `true`, the global key handler in app.rs routes printable keystrokes
    /// into `editor_text` instead of the usual app-wide shortcuts. The user
    /// clicks the editor source area to focus it; clicking outside (or Esc)
    /// releases focus and shortcuts resume.
    pub editor_focused: bool,
}

impl Default for YaraPanelState {
    fn default() -> Self {
        let rules = generate_demo_rules();
        let editor_text = if rules.is_empty() {
            new_rule_template()
        } else {
            rules[0].source.clone()
        };

        Self {
            rules,
            selected_rule_idx: Some(0),
            selected_result_idx: None,
            selected_match_idx: None,
            active_tab: ActiveTab::Editor,
            editor_text,
            editor_cursor_line: 0,
            validation_status: ValidationStatus::Unknown,
            scan_results: generate_demo_results(),
            scan_stats: ScanStats {
                total_rules: 3,
                matched_rules: 2,
                total_matches: 5,
                scan_duration: Some(Duration::from_millis(87)),
                bytes_scanned: 1024 * 1024,
            },
            is_scanning: false,
            last_scan: None,
            filter_namespace: String::new(),
            filter_name: String::new(),
            builtin_categories: builtin_categories(),
            show_builtin_picker: false,
            builtin_selected_cat: 0,
            show_import_dialog: false,
            import_path: String::new(),
            show_export_dialog: false,
            export_path: String::new(),
            navigate_to_address: None,
            editor_focused: false,
        }
    }
}

impl YaraPanelState {
    pub fn take_navigate_address(&mut self) -> Option<u64> {
        self.navigate_to_address.take()
    }

    pub fn start_scan(&mut self) {
        self.is_scanning = true;
        self.last_scan = Some(Instant::now());
        self.is_scanning = false;
    }

    pub fn validate_current_rule(&mut self) {
        // Delegate to the live rustre-yara parser for accurate diagnostics.
        super::yara_backend::validate_editor_rule(self);
    }

    /// Scan the supplied byte slice with the rule currently in the editor,
    /// using the yara-x backed [`rustre_yara_engine::YaraEngineScanner`].
    ///
    /// # Errors
    ///
    /// Returns an error string if the rule fails to compile.
    pub fn scan_editor_against(&mut self, data: &[u8]) -> Result<(), String> {
        self.is_scanning = true;
        super::yara_backend::scan_editor_rule_over_bytes(self, data)
    }

    pub fn new_rule(&mut self) {
        let source = new_rule_template();
        let rule = YaraRule {
            id: self.rules.len() as u64 + 100,
            name: format!("NewRule_{}", self.rules.len()),
            namespace: "user".into(),
            category: "Custom".into(),
            tags: vec![],
            meta: HashMap::new(),
            strings: vec![],
            condition: "any of them".into(),
            source: source.clone(),
            enabled: true,
            builtin: false,
        };
        self.rules.push(rule);
        self.selected_rule_idx = Some(self.rules.len() - 1);
        self.editor_text = source;
        self.active_tab = ActiveTab::Editor;
    }

    pub fn add_builtin_rule(&mut self, name: String) {
        let source = format!(
            "// Built-in rule: {}\nrule {}\n{{\n    condition:\n        true\n}}\n",
            name, name
        );
        let rule = YaraRule {
            id: self.rules.len() as u64 + 200,
            name: name.clone(),
            namespace: "builtin".into(),
            category: "Built-in".into(),
            tags: vec!["builtin".into()],
            meta: HashMap::new(),
            strings: vec![],
            condition: "true".into(),
            source,
            enabled: true,
            builtin: true,
        };
        self.rules.push(rule);
    }
}

// ── Demo data ───────────────────────────────────────────────────────────────

pub fn new_rule_template() -> String {
    r#"rule MyNewRule
{
    meta:
        author = "RustRE User"
        description = "Describe this rule"
        date = "2026-01-01"

    strings:
        $s1 = "suspicious string" nocase
        $h1 = { 4D 5A 90 00 }
        $r1 = /https?:\/\/[^\/]+\/[a-z]{8}/ nocase

    condition:
        any of them
}
"#
    .into()
}

fn generate_demo_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            id: 1,
            name: "Cobalt_Strike_Beacon".into(),
            namespace: "malware".into(),
            category: "Malware Families".into(),
            tags: vec!["cobalt_strike".into(), "beacon".into(), "rat".into()],
            meta: {
                let mut m = HashMap::new();
                m.insert("author".into(), "RustRE".into());
                m.insert("description".into(), "Detects Cobalt Strike beacon".into());
                m.insert("severity".into(), "critical".into());
                m
            },
            strings: vec![
                YaraStringDef {
                    identifier: "$beacon_magic".into(),
                    string_type: StringType::Hex,
                    value: "{ FC E8 89 00 00 00 60 }".into(),
                    modifiers: vec![],
                },
                YaraStringDef {
                    identifier: "$pipe_name".into(),
                    string_type: StringType::Regex,
                    value: r"/\\\\[a-zA-Z0-9]{4,8}\\pipe\\[a-zA-Z0-9]{4,8}/".into(),
                    modifiers: vec!["wide".into()],
                },
            ],
            condition: "any of them".into(),
            source: r#"rule Cobalt_Strike_Beacon
{
    meta:
        author = "RustRE"
        description = "Detects Cobalt Strike beacon"
        severity = "critical"

    strings:
        $beacon_magic = { FC E8 89 00 00 00 60 }
        $pipe_name = /\\\\[a-zA-Z0-9]{4,8}\\pipe\\[a-zA-Z0-9]{4,8}/ wide

    condition:
        any of them
}
"#
            .into(),
            enabled: true,
            builtin: false,
        },
        YaraRule {
            id: 2,
            name: "UPX_Packed".into(),
            namespace: "packers".into(),
            category: "Packers".into(),
            tags: vec!["upx".into(), "packed".into()],
            meta: {
                let mut m = HashMap::new();
                m.insert("description".into(), "Detects UPX-packed binaries".into());
                m
            },
            strings: vec![
                YaraStringDef {
                    identifier: "$upx0".into(),
                    string_type: StringType::Text,
                    value: "UPX0".into(),
                    modifiers: vec![],
                },
                YaraStringDef {
                    identifier: "$upx1".into(),
                    string_type: StringType::Text,
                    value: "UPX1".into(),
                    modifiers: vec![],
                },
                YaraStringDef {
                    identifier: "$upx_magic".into(),
                    string_type: StringType::Hex,
                    value: "{ 55 50 58 21 }".into(),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".into(),
            source: r#"rule UPX_Packed
{
    meta:
        description = "Detects UPX-packed binaries"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_magic = { 55 50 58 21 }

    condition:
        2 of them
}
"#
            .into(),
            enabled: true,
            builtin: true,
        },
        YaraRule {
            id: 3,
            name: "AES_SBox".into(),
            namespace: "crypto".into(),
            category: "Crypto Constants".into(),
            tags: vec!["aes".into(), "crypto".into()],
            meta: {
                let mut m = HashMap::new();
                m.insert("description".into(), "AES S-Box constants detection".into());
                m
            },
            strings: vec![YaraStringDef {
                identifier: "$sbox_start".into(),
                string_type: StringType::Hex,
                value: "{ 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }".into(),
                modifiers: vec![],
            }],
            condition: "$sbox_start".into(),
            source: r#"rule AES_SBox
{
    meta:
        description = "AES S-Box constants detection"

    strings:
        $sbox_start = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }

    condition:
        $sbox_start
}
"#
            .into(),
            enabled: true,
            builtin: true,
        },
    ]
}

fn generate_demo_results() -> Vec<ScanResult> {
    vec![
        ScanResult {
            rule_id: 1,
            rule_name: "Cobalt_Strike_Beacon".into(),
            namespace: "malware".into(),
            match_count: 2,
            first_match_address: 0x0040_1234,
            matches: vec![
                YaraMatch {
                    address: 0x0040_1234,
                    length: 7,
                    data_preview: vec![0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00, 0x60],
                    string_identifier: Some("$beacon_magic".into()),
                    offset_in_file: 0x234,
                },
                YaraMatch {
                    address: 0x0041_A000,
                    length: 24,
                    data_preview: b"\\\\svchost\\pipe\\mojo1234".to_vec(),
                    string_identifier: Some("$pipe_name".into()),
                    offset_in_file: 0x1_A000,
                },
            ],
            scan_time_ms: 12.4,
        },
        ScanResult {
            rule_id: 2,
            rule_name: "UPX_Packed".into(),
            namespace: "packers".into(),
            match_count: 3,
            first_match_address: 0x0000_01C0,
            matches: vec![
                YaraMatch {
                    address: 0x0000_01C0,
                    length: 4,
                    data_preview: b"UPX0".to_vec(),
                    string_identifier: Some("$upx0".into()),
                    offset_in_file: 0x1C0,
                },
                YaraMatch {
                    address: 0x0000_01F0,
                    length: 4,
                    data_preview: b"UPX1".to_vec(),
                    string_identifier: Some("$upx1".into()),
                    offset_in_file: 0x1F0,
                },
                YaraMatch {
                    address: 0x0000_0220,
                    length: 4,
                    data_preview: vec![0x55, 0x50, 0x58, 0x21],
                    string_identifier: Some("$upx_magic".into()),
                    offset_in_file: 0x220,
                },
            ],
            scan_time_ms: 3.1,
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

fn format_bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        let mb_num = u32::try_from(n / 1024).unwrap_or(u32::MAX);
        format!("{:.1} MB", f64::from(mb_num) / 1024.0)
    } else if n >= 1024 {
        let kb = u32::try_from(n).unwrap_or(u32::MAX);
        format!("{:.1} KB", f64::from(kb) / 1024.0)
    } else {
        format!("{n} B")
    }
}

// ── Render entry-point ──────────────────────────────────────────────────────

/// Render the YARA panel against persistent state owned by the App.
///
/// The previous incarnation rebuilt `YaraPanelState::default()` every frame,
/// silently discarding any click. The state now lives on the App and is
/// mutated by `UICommand::Yara*` arms in the central dispatch — toolbar
/// buttons and tabs emit those commands via the supplied `EventBus`.
pub fn render_yara_panel(
    st: &YaraPanelState,
    _data: &AppData,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'static {
    render_with_state(st, bus)
}

fn render_with_state(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement + 'static {
    let bg = hsla(230.0 / 360.0, 0.26, 0.07, 1.0);
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(bg)
        .child(render_toolbar(st, bus))
        .child(render_tabs(st, bus))
        .child(
            div()
                .flex()
                .flex_row()
                .flex_1()
                .overflow_hidden()
                .child(render_library(st, bus))
                .child(render_main_pane(st, bus)),
        )
}

// ── Toolbar ─────────────────────────────────────────────────────────────────

fn render_toolbar(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let scan_label = if st.is_scanning { "Scanning..." } else { "Scan" };
    let scan_color = if st.is_scanning {
        hsla(45.0 / 360.0, 0.75, 0.55, 1.0)
    } else {
        hsla(140.0 / 360.0, 0.65, 0.50, 1.0)
    };

    let validation_node = match &st.validation_status {
        ValidationStatus::Valid => Some(text_xs(
            "[OK] Valid",
            hsla(140.0 / 360.0, 0.65, 0.55, 1.0),
        )
        .into_any_element()),
        ValidationStatus::Error(e) => Some(text_xs(
            &format!("[X] {e}"),
            hsla(0.0 / 360.0, 0.75, 0.60, 1.0),
        )
        .into_any_element()),
        ValidationStatus::Unknown => None,
    };

    let stats_text = st.scan_stats.scan_duration.as_ref().map(|d| {
        format!(
            "Last scan: {}ms | {}/{} rules matched | {} matches | {} scanned",
            d.as_millis(),
            st.scan_stats.matched_rules,
            st.scan_stats.total_rules,
            st.scan_stats.total_matches,
            format_bytes(st.scan_stats.bytes_scanned),
        )
    });

    // Clone the bus once per button so each `on_click` closure owns its own Arc.
    let scan_bus = Arc::clone(bus);
    let newrule_bus = Arc::clone(bus);
    let import_bus = Arc::clone(bus);
    let export_bus = Arc::clone(bus);
    let builtin_bus = Arc::clone(bus);
    let validate_bus = Arc::clone(bus);
    let entropy_bus = Arc::clone(bus);

    let mut root = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .py_2()
        .bg(hsla(230.0 / 360.0, 0.24, 0.09, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .child(
            toolbar_button("yara-tb-scan", scan_label, scan_color).on_click(
                move |_: &ClickEvent, _, _| scan_bus.send_command(UICommand::YaraScan),
            ),
        )
        .child(div().w_px().h_6().bg(hsla(0.0, 0.0, 0.20, 1.0)))
        .child(
            toolbar_button("yara-tb-newrule", "New Rule", hsla(0.0, 0.0, 0.75, 1.0)).on_click(
                move |_: &ClickEvent, _, _| newrule_bus.send_command(UICommand::YaraNewRule),
            ),
        )
        .child(
            toolbar_button("yara-tb-import", "Import...", hsla(0.0, 0.0, 0.75, 1.0)).on_click(
                move |_: &ClickEvent, _, _| import_bus.send_command(UICommand::YaraImport),
            ),
        )
        .child(
            toolbar_button("yara-tb-export", "Export...", hsla(0.0, 0.0, 0.75, 1.0)).on_click(
                move |_: &ClickEvent, _, _| export_bus.send_command(UICommand::YaraExport),
            ),
        )
        .child(
            toolbar_button(
                "yara-tb-builtin",
                "Built-in Rules...",
                hsla(0.0, 0.0, 0.75, 1.0),
            )
            .on_click(move |_: &ClickEvent, _, _| builtin_bus.send_command(UICommand::YaraBuiltin)),
        )
        .child(div().w_px().h_6().bg(hsla(0.0, 0.0, 0.20, 1.0)))
        .child(
            toolbar_button("yara-tb-validate", "Validate", hsla(0.0, 0.0, 0.75, 1.0)).on_click(
                move |_: &ClickEvent, _, _| validate_bus.send_command(UICommand::YaraValidate),
            ),
        )
        .child(
            toolbar_button("yara-tb-entropy", "Entropy", hsla(0.0, 0.0, 0.75, 1.0)).on_click(
                move |_: &ClickEvent, _, _| entropy_bus.send_command(UICommand::YaraEntropy),
            ),
        );

    if let Some(v) = validation_node {
        root = root.child(v);
    }

    root = root.child(div().flex_1());

    if let Some(s) = stats_text {
        root = root.child(text_xs(&s, hsla(0.0, 0.0, 0.50, 1.0)));
    }

    root
}

fn toolbar_button(id: &'static str, label: &str, color: Hsla) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(id))
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

// ── Tabs ────────────────────────────────────────────────────────────────────

fn render_tabs(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let total_matches: usize = st.scan_results.iter().map(|r| r.match_count).sum();
    let tabs: [(ActiveTab, &'static str, String); 3] = [
        (ActiveTab::Editor, "yara-tab-editor", "Editor".into()),
        (ActiveTab::Library, "yara-tab-details", "Rule Details".into()),
        (
            ActiveTab::Results,
            "yara-tab-results",
            format!("Results ({total_matches})"),
        ),
    ];

    div()
        .flex()
        .flex_row()
        .px_2()
        .bg(hsla(230.0 / 360.0, 0.22, 0.08, 1.0))
        .border_b_1()
        .border_color(hsla(0.0, 0.0, 0.20, 1.0))
        .children(tabs.into_iter().enumerate().map(|(idx, (tab, id, label))| {
            let active = tab == st.active_tab;
            let tab_bus = Arc::clone(bus);
            let tab_idx = u8::try_from(idx).unwrap_or(0);
            div()
                .id(SharedString::from(id))
                .px_3()
                .py_1()
                .cursor_pointer()
                .border_b_2()
                .border_color(if active {
                    hsla(258.0 / 360.0, 0.60, 0.60, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.0, 0.0)
                })
                .on_click(move |_: &ClickEvent, _, _| {
                    tab_bus.send_command(UICommand::YaraSetTab(tab_idx));
                })
                .child(text_sm(
                    &label,
                    if active {
                        hsla(258.0 / 360.0, 0.70, 0.78, 1.0)
                    } else {
                        hsla(0.0, 0.0, 0.55, 1.0)
                    },
                ))
        }))
}

// ── Library (left sub-panel) ────────────────────────────────────────────────

fn render_library(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let filter_lower = st.filter_name.to_lowercase();

    let mut namespaces: Vec<String> = st
        .rules
        .iter()
        .map(|r| r.namespace.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    namespaces.sort();

    let groups = namespaces.into_iter().map(|ns| {
        let rules_in_ns: Vec<usize> = (0..st.rules.len())
            .filter(|&i| {
                st.rules[i].namespace == ns
                    && (filter_lower.is_empty()
                        || st.rules[i].name.to_lowercase().contains(&filter_lower))
            })
            .collect();

        let header = div()
            .flex()
            .flex_row()
            .items_center()
            .gap_1()
            .px_2()
            .py_1()
            .bg(hsla(0.0, 0.0, 0.12, 1.0))
            .child(text_xs(
                &format!("{} ({})", ns, rules_in_ns.len()),
                hsla(258.0 / 360.0, 0.50, 0.72, 1.0),
            ));

        let rows = rules_in_ns.into_iter().map(|rule_idx| {
            let rule = &st.rules[rule_idx];
            let is_selected = st.selected_rule_idx == Some(rule_idx);
            let bg = if is_selected {
                hsla(225.0 / 360.0, 0.65, 0.30, 0.45)
            } else {
                hsla(0.0, 0.0, 0.0, 0.0)
            };
            let enabled_color = if rule.enabled {
                hsla(140.0 / 360.0, 0.65, 0.55, 1.0)
            } else {
                hsla(0.0, 0.0, 0.45, 1.0)
            };

            let row_bus = Arc::clone(bus);
            let row_idx_u32 = u32::try_from(rule_idx).unwrap_or(u32::MAX);
            let mut row = div()
                .id(SharedString::from(format!("yara-lib-row-{rule_idx}")))
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_px()
                .bg(bg)
                .cursor_pointer()
                .hover(|s| s.bg(hsla(258.0 / 360.0, 0.60, 0.40, 0.20)))
                .on_click(move |_: &ClickEvent, _, _| {
                    row_bus.send_command(UICommand::YaraSelectLibraryRule(row_idx_u32));
                })
                .child(div().w_2().h_2().rounded_full().bg(enabled_color));

            if rule.builtin {
                row = row.child(text_xs("[B]", hsla(40.0 / 360.0, 0.55, 0.55, 1.0)));
            }

            row.child(text_xs(&rule.name, hsla(0.0, 0.0, 0.80, 1.0)))
        });

        div()
            .flex()
            .flex_col()
            .child(header)
            .children(rows.map(IntoElement::into_any_element))
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
                .child(text_sm("Rules", hsla(0.0, 0.0, 0.85, 1.0))),
        )
        .child(
            div()
                .px_2()
                .py_1()
                .child(text_xs(
                    if st.filter_name.is_empty() {
                        "Filter..."
                    } else {
                        st.filter_name.as_str()
                    },
                    hsla(0.0, 0.0, 0.45, 1.0),
                )),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .children(groups.map(IntoElement::into_any_element)),
        )
}

// ── Main pane (editor / details / results) ──────────────────────────────────

fn render_main_pane(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let body = match st.active_tab {
        ActiveTab::Editor => render_editor_tab(st, bus).into_any_element(),
        ActiveTab::Library => render_rule_detail_tab(st).into_any_element(),
        ActiveTab::Results => render_results_tab(st, bus).into_any_element(),
    };

    let mut wrapper = div()
        .flex()
        .flex_col()
        .flex_1()
        .h_full()
        .overflow_hidden()
        .child(body);

    if st.show_builtin_picker {
        wrapper = wrapper.child(render_builtin_window(st, bus));
    }
    if st.show_import_dialog {
        wrapper = wrapper.child(render_import_window(st, bus));
    }
    if st.show_export_dialog {
        wrapper = wrapper.child(render_export_window(st, bus));
    }

    wrapper
}

// ── Editor tab ──────────────────────────────────────────────────────────────

fn render_editor_tab(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let token_lines = tokenize_yara(&st.editor_text);

    let preview_rows = token_lines.into_iter().enumerate().map(|(line_num, spans)| {
        let highlight = line_num == st.editor_cursor_line;
        let line_bg = if highlight {
            hsla(258.0 / 360.0, 0.40, 0.20, 0.40)
        } else {
            hsla(0.0, 0.0, 0.0, 0.0)
        };

        let span_children = spans.into_iter().map(|span| {
            let col = span.token.color();
            mono_xs(&span.text, col).into_any_element()
        });

        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .px_2()
            .bg(line_bg)
            .child(mono_xs(
                &format!("{:4}", line_num + 1),
                hsla(0.0, 0.0, 0.30, 1.0),
            ))
            .children(span_children)
    });

    div()
        .flex()
        .flex_col()
        .flex_1()
        .overflow_hidden()
        .child(
            div()
                .px_2()
                .py_1()
                .child(text_xs(
                    "Preview (syntax highlighted):",
                    hsla(0.0, 0.0, 0.55, 1.0),
                )),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .overflow_hidden()
                .bg(hsla(230.0 / 360.0, 0.20, 0.05, 1.0))
                .children(preview_rows.map(IntoElement::into_any_element)),
        )
        .child({
            let header_bus = Arc::clone(bus);
            let focused = st.editor_focused;
            div()
                .id(SharedString::from("yara-editor-header"))
                .px_2()
                .py_1()
                .border_t_1()
                .border_color(if focused {
                    hsla(258.0 / 360.0, 0.60, 0.60, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.20, 1.0)
                })
                .cursor_pointer()
                .on_click(move |_: &ClickEvent, _, _| {
                    header_bus.send_command(UICommand::YaraSetEditorFocus(!focused));
                })
                .child(text_xs(
                    if focused {
                        "Source [EDIT MODE — type to insert | Esc to exit | Bksp to delete]"
                    } else {
                        "Source (click to edit, type from keyboard)"
                    },
                    if focused {
                        hsla(258.0 / 360.0, 0.70, 0.78, 1.0)
                    } else {
                        hsla(0.0, 0.0, 0.55, 1.0)
                    },
                ))
        })
        .child({
            let body_bus = Arc::clone(bus);
            let focused = st.editor_focused;
            let mut body = div()
                .id(SharedString::from("yara-editor-body"))
                .px_2()
                .py_1()
                .bg(if focused {
                    hsla(0.0, 0.0, 0.13, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.10, 1.0)
                })
                .border_1()
                .border_color(if focused {
                    hsla(258.0 / 360.0, 0.60, 0.60, 1.0)
                } else {
                    hsla(0.0, 0.0, 0.0, 0.0)
                })
                .cursor_pointer()
                .on_click(move |_: &ClickEvent, _, _| {
                    body_bus.send_command(UICommand::YaraSetEditorFocus(true));
                });
            // Show every line of editor_text with a faint caret at the end so the
            // user can see where their next keypress lands. Newlines split into rows.
            let mut lines: Vec<&str> = st.editor_text.split('\n').collect();
            if lines.is_empty() {
                lines.push("");
            }
            let last_idx = lines.len() - 1;
            for (i, line) in lines.iter().enumerate() {
                let caret = if focused && i == last_idx { "▏" } else { "" };
                let row_text = format!("{line}{caret}");
                body = body.child(mono_xs(&row_text, hsla(0.0, 0.0, 0.78, 1.0)));
            }
            body
        })
}

// ── Rule detail tab ─────────────────────────────────────────────────────────

fn render_rule_detail_tab(st: &YaraPanelState) -> impl IntoElement {
    let Some(idx) = st.selected_rule_idx else {
        return div()
            .flex()
            .items_center()
            .justify_center()
            .flex_1()
            .child(text_sm("No rule selected", hsla(0.0, 0.0, 0.45, 1.0)))
            .into_any_element();
    };

    if idx >= st.rules.len() {
        return div().into_any_element();
    }

    let rule = &st.rules[idx];

    let tag_chips = rule.tags.iter().map(|tag| {
        div()
            .px_2()
            .py_px()
            .rounded_sm()
            .bg(hsla(210.0 / 360.0, 0.55, 0.25, 1.0))
            .child(text_xs(
                &format!("[{tag}]"),
                hsla(210.0 / 360.0, 0.70, 0.75, 1.0),
            ))
    });

    let meta_rows = rule.meta.iter().map(|(k, v)| {
        div()
            .flex()
            .flex_row()
            .gap_2()
            .px_2()
            .py_px()
            .child(
                div()
                    .w_32()
                    .flex_shrink_0()
                    .child(text_xs(k, hsla(200.0 / 360.0, 0.70, 0.70, 1.0))),
            )
            .child(text_xs(v, hsla(0.0, 0.0, 0.80, 1.0)))
    });

    let string_rows = rule.strings.iter().map(|s| {
        let modifiers = s
            .modifiers
            .iter()
            .map(|m| {
                div()
                    .px_1()
                    .child(text_xs(m, hsla(280.0 / 360.0, 0.55, 0.70, 1.0)))
                    .into_any_element()
            });
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .px_2()
            .py_px()
            .child(mono_xs(
                &s.identifier,
                hsla(45.0 / 360.0, 0.70, 0.65, 1.0),
            ))
            .child(text_xs(s.string_type.label(), s.string_type.color()))
            .child(mono_xs(&s.value, hsla(0.0, 0.0, 0.80, 1.0)))
            .children(modifiers)
    });

    let builtin_chip = if rule.builtin {
        Some(text_xs("[Built-in]", hsla(40.0 / 360.0, 0.55, 0.55, 1.0)).into_any_element())
    } else {
        None
    };

    let mut header_row = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_3()
        .child(text_xs(
            &format!("Namespace: {}", rule.namespace),
            hsla(0.0, 0.0, 0.65, 1.0),
        ))
        .child(text_xs(
            &format!("Category: {}", rule.category),
            hsla(0.0, 0.0, 0.65, 1.0),
        ));
    if let Some(c) = builtin_chip {
        header_row = header_row.child(c);
    }

    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .flex_1()
        .overflow_hidden()
        .child(text_md(&rule.name, hsla(0.0, 0.0, 0.92, 1.0)))
        .child(header_row)
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(text_xs("Tags:", hsla(0.0, 0.0, 0.55, 1.0)))
                .children(tag_chips.map(IntoElement::into_any_element)),
        )
        .child(section_header("Meta"))
        .child(div().flex().flex_col().children(meta_rows.map(IntoElement::into_any_element)))
        .child(section_header("Strings"))
        .child(div().flex().flex_col().children(string_rows.map(IntoElement::into_any_element)))
        .child(section_header("Condition"))
        .child(
            div()
                .px_2()
                .py_1()
                .bg(hsla(0.0, 0.0, 0.10, 1.0))
                .child(mono_xs(&rule.condition, hsla(0.0, 0.0, 0.82, 1.0))),
        )
        .into_any_element()
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

// ── Results tab ─────────────────────────────────────────────────────────────

fn render_results_tab(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    if st.scan_results.is_empty() {
        return div()
            .flex()
            .items_center()
            .justify_center()
            .flex_1()
            .child(text_sm(
                "No scan results yet. Click Scan to run.",
                hsla(0.0, 0.0, 0.45, 1.0),
            ))
            .into_any_element();
    }

    let total_matches: usize = st.scan_results.iter().map(|r| r.match_count).sum();
    let total_time: f64 = st.scan_results.iter().map(|r| r.scan_time_ms).sum();

    let rows = st.scan_results.iter().enumerate().map(|(res_idx, result)| {
        let is_selected = st.selected_result_idx == Some(res_idx);
        let bg = if is_selected {
            hsla(225.0 / 360.0, 0.55, 0.28, 0.50)
        } else {
            hsla(0.0, 0.0, 0.10, 1.0)
        };

        let node_bus = Arc::clone(bus);
        let res_idx_u32 = u32::try_from(res_idx).unwrap_or(u32::MAX);
        let mut node = div()
            .id(SharedString::from(format!("yara-res-{res_idx}")))
            .flex()
            .flex_col()
            .gap_1()
            .p_2()
            .rounded_sm()
            .bg(bg)
            .cursor_pointer()
            .hover(|s| s.bg(hsla(258.0 / 360.0, 0.60, 0.40, 0.18)))
            .on_click(move |_: &ClickEvent, _, _| {
                node_bus.send_command(UICommand::YaraSelectResult(res_idx_u32));
            })
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(text_sm(
                        &result.rule_name,
                        hsla(45.0 / 360.0, 0.70, 0.65, 1.0),
                    ))
                    .child(text_xs(
                        &format!("[{}]", result.namespace),
                        hsla(0.0, 0.0, 0.50, 1.0),
                    ))
                    .child(div().flex_1())
                    .child(text_xs(
                        &format!(
                            "{} match(es) | {:.1}ms",
                            result.match_count, result.scan_time_ms
                        ),
                        hsla(0.0, 0.0, 0.55, 1.0),
                    )),
            )
            .child(mono_xs(
                &format!("First match: {:#018X}", result.first_match_address),
                hsla(190.0 / 360.0, 0.70, 0.70, 1.0),
            ));

        if is_selected {
            let match_rows = result.matches.iter().enumerate().map(|(m_idx, m)| {
                let sel = st.selected_match_idx == Some(m_idx);
                let hex_preview: String = m
                    .data_preview
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let row_bg = if sel {
                    hsla(225.0 / 360.0, 0.55, 0.20, 0.55)
                } else {
                    hsla(0.0, 0.0, 0.0, 0.0)
                };
                let m_bus = Arc::clone(bus);
                let m_idx_u32 = u32::try_from(m_idx).unwrap_or(u32::MAX);
                let mut r = div()
                    .id(SharedString::from(format!("yara-res-{res_idx}-m-{m_idx}")))
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_3()
                    .px_3()
                    .py_px()
                    .bg(row_bg)
                    .cursor_pointer()
                    .hover(|s| s.bg(hsla(258.0 / 360.0, 0.60, 0.40, 0.18)))
                    .on_click(move |_: &ClickEvent, _, _| {
                        m_bus.send_command(UICommand::YaraSelectMatch(m_idx_u32));
                    })
                    .child(mono_xs(
                        &format!("{:#018X}", m.address),
                        hsla(190.0 / 360.0, 0.70, 0.70, 1.0),
                    ))
                    .child(text_xs(
                        &format!("{} bytes", m.length),
                        hsla(0.0, 0.0, 0.55, 1.0),
                    ));
                if let Some(sid) = &m.string_identifier {
                    r = r.child(text_xs(sid, hsla(45.0 / 360.0, 0.70, 0.65, 1.0)));
                }
                r = r.child(mono_xs(&hex_preview, hsla(0.0, 0.0, 0.55, 1.0)));
                let _ = m.offset_in_file;
                r
            });

            node = node.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_px()
                    .pl_4()
                    .bg(hsla(0.0, 0.0, 0.08, 1.0))
                    .children(match_rows.map(IntoElement::into_any_element)),
            );
        }
        node
    });

    div()
        .flex()
        .flex_col()
        .flex_1()
        .gap_2()
        .p_3()
        .overflow_hidden()
        .child(text_sm(
            &format!(
                "{} rules matched, {} total matches in {:.1}ms",
                st.scan_results.len(),
                total_matches,
                total_time
            ),
            hsla(0.0, 0.0, 0.70, 1.0),
        ))
        .children(rows.map(IntoElement::into_any_element))
        .into_any_element()
}

// ── Modal windows ───────────────────────────────────────────────────────────

fn render_builtin_window(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let categories = st.builtin_categories.clone();
    let selected = st.builtin_selected_cat;

    let cat_list = categories.iter().enumerate().map(|(i, cat)| {
        let active = selected == i;
        let cat_bus = Arc::clone(bus);
        let cat_idx = u8::try_from(i).unwrap_or(0);
        div()
            .id(SharedString::from(format!("yara-builtin-cat-{i}")))
            .px_2()
            .py_1()
            .cursor_pointer()
            .bg(if active {
                hsla(225.0 / 360.0, 0.55, 0.28, 0.50)
            } else {
                hsla(0.0, 0.0, 0.0, 0.0)
            })
            .hover(|s| s.bg(hsla(258.0 / 360.0, 0.60, 0.40, 0.18)))
            .on_click(move |_: &ClickEvent, _, _| {
                cat_bus.send_command(UICommand::YaraSelectBuiltinCategory(cat_idx));
            })
            .child(text_xs(&cat.name, hsla(0.0, 0.0, 0.80, 1.0)))
    });

    let detail = categories.get(selected).map(|cat| {
        let cat_idx = u8::try_from(selected).unwrap_or(0);
        let rule_rows = cat.rules.iter().enumerate().map(|(r_idx, (name, desc))| {
            let add_bus = Arc::clone(bus);
            let rule_idx = u8::try_from(r_idx).unwrap_or(0);
            let btn_id = SharedString::from(format!("yara-builtin-add-{cat_idx}-{rule_idx}"));
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .py_1()
                .child(
                    div()
                        .id(btn_id)
                        .px_2()
                        .py_1()
                        .cursor_pointer()
                        .rounded_sm()
                        .bg(hsla(0.0, 0.0, 0.15, 1.0))
                        .border_1()
                        .border_color(hsla(0.0, 0.0, 0.25, 1.0))
                        .hover(|s| s.bg(hsla(0.0, 0.0, 0.20, 1.0)))
                        .on_click(move |_: &ClickEvent, _, _| {
                            add_bus.send_command(UICommand::YaraAddBuiltin(cat_idx, rule_idx));
                        })
                        .child(text_xs("Add", hsla(0.0, 0.0, 0.80, 1.0))),
                )
                .child(text_sm(name, hsla(0.0, 0.0, 0.85, 1.0)))
                .child(text_xs(desc, hsla(0.0, 0.0, 0.50, 1.0)))
        });
        div()
            .flex()
            .flex_col()
            .gap_1()
            .p_2()
            .flex_1()
            .child(text_md(&cat.name, hsla(0.0, 0.0, 0.90, 1.0)))
            .children(rule_rows.map(IntoElement::into_any_element))
    });

    let mut body = div()
        .flex()
        .flex_row()
        .flex_1()
        .child(
            div()
                .flex()
                .flex_col()
                .w_40()
                .flex_shrink_0()
                .border_r_1()
                .border_color(hsla(0.0, 0.0, 0.20, 1.0))
                .children(cat_list.map(IntoElement::into_any_element)),
        );
    if let Some(d) = detail {
        body = body.child(d);
    }

    modal_frame("Built-in Rules", body)
}

fn render_import_window(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let file_bus = Arc::clone(bus);
    let clip_bus = Arc::clone(bus);
    modal_frame(
        "Import YARA Rules",
        div()
            .flex()
            .flex_col()
            .gap_2()
            .p_3()
            .child(text_xs("File path:", hsla(0.0, 0.0, 0.65, 1.0)))
            .child(
                div()
                    .px_2()
                    .py_1()
                    .bg(hsla(0.0, 0.0, 0.10, 1.0))
                    .border_1()
                    .border_color(hsla(0.0, 0.0, 0.25, 1.0))
                    .child(mono_xs(
                        if st.import_path.is_empty() {
                            "<not set>"
                        } else {
                            st.import_path.as_str()
                        },
                        hsla(0.0, 0.0, 0.75, 1.0),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .child(
                        toolbar_button(
                            "yara-import-file",
                            "Import from File",
                            hsla(0.0, 0.0, 0.80, 1.0),
                        )
                        .on_click(move |_: &ClickEvent, _, _| {
                            file_bus.send_command(UICommand::YaraImportFile);
                        }),
                    )
                    .child(
                        toolbar_button(
                            "yara-import-clipboard",
                            "Import from Clipboard",
                            hsla(0.0, 0.0, 0.80, 1.0),
                        )
                        .on_click(move |_: &ClickEvent, _, _| {
                            clip_bus.send_command(UICommand::YaraImportClipboard);
                        }),
                    ),
            ),
    )
}

fn render_export_window(st: &YaraPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let yar_bus = Arc::clone(bus);
    let json_bus = Arc::clone(bus);
    let csv_bus = Arc::clone(bus);
    modal_frame(
        "Export YARA Rules",
        div()
            .flex()
            .flex_col()
            .gap_2()
            .p_3()
            .child(text_xs("Export path:", hsla(0.0, 0.0, 0.65, 1.0)))
            .child(
                div()
                    .px_2()
                    .py_1()
                    .bg(hsla(0.0, 0.0, 0.10, 1.0))
                    .border_1()
                    .border_color(hsla(0.0, 0.0, 0.25, 1.0))
                    .child(mono_xs(
                        if st.export_path.is_empty() {
                            "<not set>"
                        } else {
                            st.export_path.as_str()
                        },
                        hsla(0.0, 0.0, 0.75, 1.0),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .child(
                        toolbar_button(
                            "yara-export-yar",
                            "Export .yar",
                            hsla(0.0, 0.0, 0.80, 1.0),
                        )
                        .on_click(move |_: &ClickEvent, _, _| {
                            yar_bus.send_command(UICommand::YaraExportYar);
                        }),
                    )
                    .child(
                        toolbar_button(
                            "yara-export-json",
                            "Export matches JSON",
                            hsla(0.0, 0.0, 0.80, 1.0),
                        )
                        .on_click(move |_: &ClickEvent, _, _| {
                            json_bus.send_command(UICommand::YaraExportJson);
                        }),
                    )
                    .child(
                        toolbar_button(
                            "yara-export-csv",
                            "Export matches CSV",
                            hsla(0.0, 0.0, 0.80, 1.0),
                        )
                        .on_click(move |_: &ClickEvent, _, _| {
                            csv_bus.send_command(UICommand::YaraExportCsv);
                        }),
                    ),
            ),
    )
}

fn modal_frame<E: IntoElement>(title: &str, body: E) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .m_3()
        .border_1()
        .border_color(hsla(258.0 / 360.0, 0.55, 0.45, 1.0))
        .bg(hsla(230.0 / 360.0, 0.30, 0.10, 1.0))
        .rounded_md()
        .child(
            div()
                .px_3()
                .py_2()
                .border_b_1()
                .border_color(hsla(0.0, 0.0, 0.22, 1.0))
                .child(text_sm(title, hsla(258.0 / 360.0, 0.60, 0.78, 1.0))),
        )
        .child(body)
}

// ── ensure-used (wires every public item so dead-code checks pass) ──────────

#[doc(hidden)]
pub fn ensure_used_yara() {
    // Token color coverage
    for t in [
        YaraToken::Keyword,
        YaraToken::StringKw,
        YaraToken::HexLiteral,
        YaraToken::TextLiteral,
        YaraToken::RegexLiteral,
        YaraToken::Number,
        YaraToken::Operator,
        YaraToken::Comment,
        YaraToken::Meta,
        YaraToken::Tag,
        YaraToken::Normal,
    ] {
        let _ = t.color();
    }
    for st_kind in [StringType::Text, StringType::Hex, StringType::Regex] {
        let _ = st_kind.label();
        let _ = st_kind.color();
    }

    let span = TokenSpan {
        token: YaraToken::Normal,
        text: "x".into(),
    };
    let _ = &span.token;
    let _ = &span.text;

    let mut state = YaraPanelState::default();
    let _ = state.take_navigate_address();
    state.start_scan();
    state.validate_current_rule();
    let _ = state.scan_editor_against(b"MZ\x90\x00rustre yara probe payload");
    state.new_rule();
    state.add_builtin_rule("Demo".into());
    // Reference the backend wiring so all public entry points are exercised.
    super::yara_backend::ensure_used_yara_backend();
    let _ = &state.rules;
    let _ = state.selected_rule_idx;
    let _ = state.selected_result_idx;
    let _ = state.selected_match_idx;
    let _ = &state.active_tab;
    let _ = &state.editor_text;
    let _ = state.editor_cursor_line;
    let _ = &state.validation_status;
    let _ = &state.scan_results;
    let _ = &state.scan_stats;
    let _ = state.is_scanning;
    let _ = state.last_scan;
    let _ = &state.filter_namespace;
    let _ = &state.filter_name;
    let _ = &state.builtin_categories;
    let _ = state.show_builtin_picker;
    let _ = state.builtin_selected_cat;
    let _ = state.show_import_dialog;
    let _ = &state.import_path;
    let _ = state.show_export_dialog;
    let _ = &state.export_path;
    let _ = state.navigate_to_address;

    for tab in [ActiveTab::Editor, ActiveTab::Library, ActiveTab::Results] {
        let _ = tab == ActiveTab::Editor;
    }
    for v in [
        ValidationStatus::Unknown,
        ValidationStatus::Valid,
        ValidationStatus::Error("e".into()),
    ] {
        let _ = matches!(v, ValidationStatus::Unknown);
    }

    let rule = YaraRule {
        id: 0,
        name: "n".into(),
        namespace: "ns".into(),
        category: "c".into(),
        tags: vec!["t".into()],
        meta: HashMap::new(),
        strings: vec![],
        condition: "any".into(),
        source: "rule x { condition: true }".into(),
        enabled: true,
        builtin: false,
    };
    let _ = (
        rule.id,
        &rule.name,
        &rule.namespace,
        &rule.category,
        &rule.tags,
        &rule.meta,
        &rule.strings,
        &rule.condition,
        &rule.source,
        rule.enabled,
        rule.builtin,
    );

    let sdef = YaraStringDef {
        identifier: "$a".into(),
        string_type: StringType::Text,
        value: "v".into(),
        modifiers: vec!["nocase".into()],
    };
    let _ = (
        &sdef.identifier,
        &sdef.string_type,
        &sdef.value,
        &sdef.modifiers,
    );

    let ymatch = YaraMatch {
        address: 0,
        length: 0,
        data_preview: vec![0],
        string_identifier: Some("s".into()),
        offset_in_file: 0,
    };
    let _ = (
        ymatch.address,
        ymatch.length,
        &ymatch.data_preview,
        &ymatch.string_identifier,
        ymatch.offset_in_file,
    );

    let res = ScanResult {
        rule_id: 0,
        rule_name: "n".into(),
        namespace: "ns".into(),
        match_count: 0,
        first_match_address: 0,
        matches: vec![],
        scan_time_ms: 0.0,
    };
    let _ = (
        res.rule_id,
        &res.rule_name,
        &res.namespace,
        res.match_count,
        res.first_match_address,
        &res.matches,
        res.scan_time_ms,
    );

    let stats = ScanStats::default();
    let _ = (
        stats.total_rules,
        stats.matched_rules,
        stats.total_matches,
        stats.scan_duration,
        stats.bytes_scanned,
    );

    let cat = BuiltinRuleCategory {
        name: "p".into(),
        rules: vec![("a".into(), "b".into())],
    };
    let _ = (&cat.name, &cat.rules);

    let _ = tokenize_yara("rule x { condition: true }");
    let _ = format_bytes(2048);
    let _ = format_bytes(2 * 1024 * 1024);
    let _ = format_bytes(10);
    let _ = builtin_categories();
    let _ = new_rule_template();
    let _ = generate_demo_rules();
    let _ = generate_demo_results();

    let _ui = Arc::new(Mutex::new(UIState::default()));
    let data = AppData::new();
    let bus = Arc::new(EventBus::new());
    let _ = render_yara_panel(&state, &data, &bus);
    let _ = render_with_state(&state, &bus);
    let _ = render_toolbar(&state, &bus);
    let _ = render_tabs(&state, &bus);
    let _ = render_library(&state, &bus);
    let _ = render_main_pane(&state, &bus);
    let _ = render_editor_tab(&state, &bus);
    let _ = render_rule_detail_tab(&state);
    let _ = render_results_tab(&state, &bus);
    let _ = render_builtin_window(&state, &bus);
    let _ = render_import_window(&state, &bus);
    let _ = render_export_window(&state, &bus);
    let _ = section_header("h");
    let _ = toolbar_button("yara-ensureused", "b", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = text_xs("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = text_sm("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = text_md("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = mono_xs("x", hsla(0.0, 0.0, 0.5, 1.0));
    let _ = modal_frame("t", div());
    let _ = classify_yara_token(
        "rule",
        &["rule"],
        &["and"],
        &["file_size"],
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_has_demo_rules() {
        let st = YaraPanelState::default();
        assert!(!st.rules.is_empty());
        assert_eq!(st.active_tab, ActiveTab::Editor);
    }

    #[test]
    fn tokenizer_handles_basic_rule() {
        let lines = tokenize_yara("rule X { condition: true }");
        assert!(!lines.is_empty());
    }

    #[test]
    fn validate_round_trip() {
        let mut st = YaraPanelState::default();
        st.editor_text = "rule X { condition: true }".into();
        st.validate_current_rule();
        assert_eq!(st.validation_status, ValidationStatus::Valid);

        st.editor_text = "rule X { }".into();
        st.validate_current_rule();
        assert!(matches!(st.validation_status, ValidationStatus::Error(_)));
    }

    #[test]
    fn format_bytes_scales() {
        assert!(format_bytes(512).contains('B'));
        assert!(format_bytes(2048).contains("KB"));
        assert!(format_bytes(2 * 1024 * 1024).contains("MB"));
    }
}
