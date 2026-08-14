// rustre-plugin-api/src/plugin_view_api.rs
//
// Plugin view/UI API: disassembly panels, hex view panels, graph views,
// toolbar buttons, context menu items, keyboard shortcuts, notifications.

use std::collections::HashMap;
use std::sync::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// ViewHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque handle identifying an open view panel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ViewHandle(pub u64);

impl ViewHandle {
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ViewHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "view#{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PanelConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Panel position hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelPosition {
    Left,
    Right,
    Bottom,
    Center,
    Floating,
}

/// Configuration for creating a new panel.
#[derive(Debug, Clone)]
pub struct PanelConfig {
    /// Display title for the panel tab.
    pub title: String,
    /// Preferred position in the UI layout.
    pub position: PanelPosition,
    /// Initial width in pixels (hint only).
    pub width: u32,
    /// Initial height in pixels (hint only).
    pub height: u32,
    /// Whether the panel can be floated.
    pub floatable: bool,
    /// Whether the panel can be closed by the user.
    pub closable: bool,
    /// Optional icon path or name.
    pub icon: Option<String>,
}

impl PanelConfig {
    /// Create a minimal panel configuration.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            position: PanelPosition::Center,
            width: 800,
            height: 600,
            floatable: true,
            closable: true,
            icon: None,
        }
    }

    /// Set position.
    #[must_use]
    pub const fn with_position(mut self, pos: PanelPosition) -> Self {
        self.position = pos;
        self
    }

    /// Set dimensions.
    #[must_use]
    pub const fn with_size(mut self, w: u32, h: u32) -> Self {
        self.width = w;
        self.height = h;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DisasmPanelConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Syntax highlight style for disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmTheme {
    Default,
    Solarized,
    Monokai,
    Dracula,
    HighContrast,
}

/// Configuration for a disassembly panel.
#[derive(Debug, Clone)]
pub struct DisasmPanelConfig {
    pub base: PanelConfig,
    /// Virtual address to initially navigate to.
    pub initial_address: u64,
    /// Architecture name for syntax highlighting.
    pub arch: String,
    /// Theme.
    pub theme: DisasmTheme,
    /// Show address column.
    pub show_address: bool,
    /// Show raw bytes column.
    pub show_bytes: bool,
    /// Show instruction comments.
    pub show_comments: bool,
    /// Maximum number of instructions to render at once.
    pub render_limit: usize,
}

impl DisasmPanelConfig {
    #[must_use]
    pub fn new(title: impl Into<String>, initial_address: u64) -> Self {
        Self {
            base: PanelConfig::new(title),
            initial_address,
            arch: String::from("x86_64"),
            theme: DisasmTheme::Default,
            show_address: true,
            show_bytes: true,
            show_comments: true,
            render_limit: 512,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexPanelConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a hex-view panel.
#[derive(Debug, Clone)]
pub struct HexPanelConfig {
    pub base: PanelConfig,
    /// Virtual address to initially display.
    pub initial_address: u64,
    /// Number of bytes per row.
    pub bytes_per_row: usize,
    /// Show ASCII sidebar.
    pub show_ascii: bool,
    /// Show decoded integers (u8/u16/u32/u64).
    pub show_decoded: bool,
    /// Group bytes by N (1, 2, 4, 8).
    pub group_by: usize,
}

impl HexPanelConfig {
    #[must_use]
    pub fn new(title: impl Into<String>, initial_address: u64) -> Self {
        Self {
            base: PanelConfig::new(title),
            initial_address,
            bytes_per_row: 16,
            show_ascii: true,
            show_decoded: false,
            group_by: 1,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Type of graph to display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphKind {
    ControlFlow,
    CallGraph,
    DataFlow,
    DependencyGraph,
    Custom,
}

/// Graph layout algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphLayout {
    LayeredTopDown,
    LayeredBottomUp,
    ForceDirected,
    Radial,
    Tree,
}

/// Configuration for a graph view panel.
#[derive(Debug, Clone)]
pub struct GraphConfig {
    pub base: PanelConfig,
    /// What kind of graph to show.
    pub kind: GraphKind,
    /// Layout algorithm.
    pub layout: GraphLayout,
    /// Root function/node address.
    pub root_addr: Option<u64>,
    /// Maximum depth to render.
    pub max_depth: usize,
    /// Whether to show node labels.
    pub show_labels: bool,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Zoom level (1.0 = 100%).
    pub zoom: f32,
}

impl GraphConfig {
    #[must_use]
    pub fn control_flow(title: impl Into<String>, root_addr: u64) -> Self {
        Self {
            base: PanelConfig::new(title),
            kind: GraphKind::ControlFlow,
            layout: GraphLayout::LayeredTopDown,
            root_addr: Some(root_addr),
            max_depth: 20,
            show_labels: true,
            show_edge_labels: false,
            zoom: 1.0,
        }
    }

    #[must_use]
    pub fn call_graph(title: impl Into<String>) -> Self {
        Self {
            base: PanelConfig::new(title),
            kind: GraphKind::CallGraph,
            layout: GraphLayout::ForceDirected,
            root_addr: None,
            max_depth: 5,
            show_labels: true,
            show_edge_labels: false,
            zoom: 1.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MenuEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Where a context menu item should appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuContext {
    DisasmView,
    HexView,
    FunctionList,
    StringList,
    GlobalMenu(String),
}

/// A single context menu item contributed by a plugin.
#[derive(Debug, Clone)]
pub struct MenuEntry {
    /// Unique identifier for this entry.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Tooltip text.
    pub tooltip: Option<String>,
    /// Optional sub-menu path (e.g. "Plugin > My Plugin").
    pub submenu_path: Option<String>,
    /// Context in which the entry appears.
    pub context: MenuContext,
    /// Whether the item is initially enabled.
    pub enabled: bool,
    /// Icon name / path.
    pub icon: Option<String>,
    /// Keyboard shortcut displayed next to the label.
    pub shortcut_hint: Option<String>,
}

impl MenuEntry {
    /// Create a minimal context menu entry.
    #[must_use]
    pub fn new(id: impl Into<String>, label: impl Into<String>, context: MenuContext) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            tooltip: None,
            submenu_path: None,
            context,
            enabled: true,
            icon: None,
            shortcut_hint: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolbarButton
// ─────────────────────────────────────────────────────────────────────────────

/// A button contributed to the main toolbar.
#[derive(Debug, Clone)]
pub struct ToolbarButton {
    /// Unique identifier.
    pub id: String,
    /// Tooltip / accessible label.
    pub tooltip: String,
    /// Icon path or name.
    pub icon: Option<String>,
    /// Position hint (lower = further left).
    pub position: u32,
    /// Whether the button is checkable (toggle).
    pub checkable: bool,
    /// Current checked state (only meaningful when `checkable` is `true`).
    pub checked: bool,
    /// Whether the button is enabled.
    pub enabled: bool,
}

impl ToolbarButton {
    /// Create a standard (non-toggle) button.
    #[must_use]
    pub fn new(id: impl Into<String>, tooltip: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tooltip: tooltip.into(),
            icon: None,
            position: 100,
            checkable: false,
            checked: false,
            enabled: true,
        }
    }

    /// Create a toggle button.
    #[must_use]
    pub fn toggle(id: impl Into<String>, tooltip: impl Into<String>) -> Self {
        let mut b = Self::new(id, tooltip);
        b.checkable = true;
        b
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KeyboardShortcut
// ─────────────────────────────────────────────────────────────────────────────

/// Modifier keys bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modifiers(pub u8);

impl Modifiers {
    pub const NONE:  Self = Self(0b0000);
    pub const SHIFT: Self = Self(0b0001);
    pub const CTRL:  Self = Self(0b0010);
    pub const ALT:   Self = Self(0b0100);
    pub const META:  Self = Self(0b1000);

    #[must_use]
    pub const fn has_ctrl(self)  -> bool { self.0 & Self::CTRL.0  != 0 }
    #[must_use]
    pub const fn has_shift(self) -> bool { self.0 & Self::SHIFT.0 != 0 }
    #[must_use]
    pub const fn has_alt(self)   -> bool { self.0 & Self::ALT.0   != 0 }
}

/// A keyboard shortcut registration.
#[derive(Debug, Clone)]
pub struct KeyboardShortcut {
    /// Action identifier this shortcut triggers.
    pub action_id: String,
    /// Modifier keys.
    pub modifiers: Modifiers,
    /// Key code (ASCII for printable, or a special code > 127).
    pub key: u32,
    /// Human-readable representation (e.g. "Ctrl+F5").
    pub display: String,
    /// Context in which this shortcut is active.
    pub context: ShortcutContext,
}

/// Context in which a shortcut is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutContext {
    Global,
    DisasmView,
    HexView,
    GraphView,
    AnyView,
}

impl KeyboardShortcut {
    #[must_use]
    pub fn global(action_id: impl Into<String>, modifiers: Modifiers, key: u32) -> Self {
        let display = format_shortcut(modifiers, key);
        Self {
            action_id: action_id.into(),
            modifiers,
            key,
            display,
            context: ShortcutContext::Global,
        }
    }
}

fn format_shortcut(mods: Modifiers, key: u32) -> String {
    let mut parts = Vec::new();
    if mods.has_ctrl()  { parts.push("Ctrl"); }
    if mods.has_shift() { parts.push("Shift"); }
    if mods.has_alt()   { parts.push("Alt"); }
    let key_char = if key < 128 && (key as u8).is_ascii_alphabetic() {
        ((key as u8).to_ascii_uppercase() as char).to_string()
    } else {
        format!("Key{key}")
    };
    parts.push(key_char.as_str());
    parts.join("+")
}

// ─────────────────────────────────────────────────────────────────────────────
// NotificationLevel
// ─────────────────────────────────────────────────────────────────────────────

/// Severity level for a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// A notification shown to the user.
#[derive(Debug, Clone)]
pub struct Notification {
    pub level: NotificationLevel,
    pub title: String,
    pub message: String,
    /// Duration in milliseconds (0 = persistent).
    pub duration_ms: u32,
    /// Optional action label and callback id.
    pub action: Option<(String, u64)>,
}

impl Notification {
    #[must_use]
    pub fn info(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level: NotificationLevel::Info,
            title: title.into(),
            message: message.into(),
            duration_ms: 3000,
            action: None,
        }
    }

    #[must_use]
    pub fn error(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level: NotificationLevel::Error,
            title: title.into(),
            message: message.into(),
            duration_ms: 0,
            action: None,
        }
    }

    #[must_use]
    pub const fn with_duration(mut self, ms: u32) -> Self {
        self.duration_ms = ms;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ViewApi — trait defining the view/UI API surface
// ─────────────────────────────────────────────────────────────────────────────

/// Trait providing the plugin view/UI API.
pub trait ViewApi: Send + Sync {
    /// Open a disassembly panel. Returns a handle.
    fn open_disasm_panel(&self, cfg: DisasmPanelConfig) -> ViewHandle;

    /// Open a hex-view panel. Returns a handle.
    fn open_hex_panel(&self, cfg: HexPanelConfig) -> ViewHandle;

    /// Open a graph view panel. Returns a handle.
    fn open_graph_panel(&self, cfg: GraphConfig) -> ViewHandle;

    /// Close a panel by handle.
    fn close_panel(&self, handle: &ViewHandle);

    /// Navigate an open view to a specific address.
    fn navigate_to(&self, handle: &ViewHandle, addr: u64);

    /// Add a context menu entry.
    fn add_menu_entry(&self, entry: MenuEntry, handler: Box<dyn Fn(u64) + Send + Sync + 'static>);

    /// Remove a context menu entry.
    fn remove_menu_entry(&self, id: &str);

    /// Add a toolbar button.
    fn add_toolbar_button(&self, button: ToolbarButton, handler: Box<dyn Fn() + Send + Sync + 'static>);

    /// Remove a toolbar button.
    fn remove_toolbar_button(&self, id: &str);

    /// Register a keyboard shortcut.
    fn register_shortcut(&self, shortcut: KeyboardShortcut, handler: Box<dyn Fn() + Send + Sync + 'static>);

    /// Unregister a keyboard shortcut by `action_id`.
    fn unregister_shortcut(&self, action_id: &str);

    /// Show a notification.
    fn show_notification(&self, notification: Notification);

    /// Highlight a range of addresses in all open views.
    fn highlight_range(&self, start: u64, end: u64, color: u32);

    /// Clear all highlights set by this plugin.
    fn clear_highlights(&self);
}

// ─────────────────────────────────────────────────────────────────────────────
// MockViewApi — in-memory implementation for testing
// ─────────────────────────────────────────────────────────────────────────────

type HandlerBox<T> = Box<dyn Fn(T) + Send + Sync + 'static>;

/// In-memory mock implementation of [`ViewApi`] for unit testing.
pub struct MockViewApi {
    next_id: Mutex<u64>,
    panels: Mutex<HashMap<u64, String>>, // handle_id → title
    menu_entries: Mutex<HashMap<String, (MenuEntry, HandlerBox<u64>)>>,
    toolbar_buttons: Mutex<HashMap<String, (ToolbarButton, Box<dyn Fn() + Send + Sync + 'static>)>>,
    shortcuts: Mutex<HashMap<String, (KeyboardShortcut, Box<dyn Fn() + Send + Sync + 'static>)>>,
    notifications: Mutex<Vec<Notification>>,
    highlights: Mutex<Vec<(u64, u64, u32)>>,
}

impl MockViewApi {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: Mutex::new(1),
            panels: Mutex::new(HashMap::new()),
            menu_entries: Mutex::new(HashMap::new()),
            toolbar_buttons: Mutex::new(HashMap::new()),
            shortcuts: Mutex::new(HashMap::new()),
            notifications: Mutex::new(Vec::new()),
            highlights: Mutex::new(Vec::new()),
        }
    }

    fn alloc_id(&self) -> u64 {
        let mut n = self.next_id.lock().unwrap();
        let id = *n;
        *n += 1;
        id
    }

    /// Return all notifications sent so far.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn notifications(&self) -> Vec<Notification> {
        self.notifications.lock().unwrap().clone()
    }

    /// Number of currently open panels.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn open_panel_count(&self) -> usize {
        self.panels.lock().unwrap().len()
    }

    /// Number of registered menu entries.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn menu_entry_count(&self) -> usize {
        self.menu_entries.lock().unwrap().len()
    }

    /// Number of registered shortcuts.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn shortcut_count(&self) -> usize {
        self.shortcuts.lock().unwrap().len()
    }

    /// Fire a menu handler by entry id (pass address 0 for testing).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn trigger_menu(&self, id: &str, addr: u64) {
        let entries = self.menu_entries.lock().unwrap();
        if let Some((_, handler)) = entries.get(id) {
            handler(addr);
        }
    }
}

impl Default for MockViewApi {
    fn default() -> Self { Self::new() }
}

impl ViewApi for MockViewApi {
    fn open_disasm_panel(&self, cfg: DisasmPanelConfig) -> ViewHandle {
        let id = self.alloc_id();
        self.panels.lock().unwrap().insert(id, cfg.base.title);
        ViewHandle::new(id)
    }

    fn open_hex_panel(&self, cfg: HexPanelConfig) -> ViewHandle {
        let id = self.alloc_id();
        self.panels.lock().unwrap().insert(id, cfg.base.title);
        ViewHandle::new(id)
    }

    fn open_graph_panel(&self, cfg: GraphConfig) -> ViewHandle {
        let id = self.alloc_id();
        self.panels.lock().unwrap().insert(id, cfg.base.title);
        ViewHandle::new(id)
    }

    fn close_panel(&self, handle: &ViewHandle) {
        self.panels.lock().unwrap().remove(&handle.0);
    }

    fn navigate_to(&self, _handle: &ViewHandle, _addr: u64) {}

    fn add_menu_entry(&self, entry: MenuEntry, handler: Box<dyn Fn(u64) + Send + Sync + 'static>) {
        let id = entry.id.clone();
        self.menu_entries.lock().unwrap().insert(id, (entry, handler));
    }

    fn remove_menu_entry(&self, id: &str) {
        self.menu_entries.lock().unwrap().remove(id);
    }

    fn add_toolbar_button(&self, button: ToolbarButton, handler: Box<dyn Fn() + Send + Sync + 'static>) {
        let id = button.id.clone();
        self.toolbar_buttons.lock().unwrap().insert(id, (button, handler));
    }

    fn remove_toolbar_button(&self, id: &str) {
        self.toolbar_buttons.lock().unwrap().remove(id);
    }

    fn register_shortcut(&self, shortcut: KeyboardShortcut, handler: Box<dyn Fn() + Send + Sync + 'static>) {
        let id = shortcut.action_id.clone();
        self.shortcuts.lock().unwrap().insert(id, (shortcut, handler));
    }

    fn unregister_shortcut(&self, action_id: &str) {
        self.shortcuts.lock().unwrap().remove(action_id);
    }

    fn show_notification(&self, notification: Notification) {
        self.notifications.lock().unwrap().push(notification);
    }

    fn highlight_range(&self, start: u64, end: u64, color: u32) {
        self.highlights.lock().unwrap().push((start, end, color));
    }

    fn clear_highlights(&self) {
        self.highlights.lock().unwrap().clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn open_close_disasm_panel() {
        let api = MockViewApi::new();
        let handle = api.open_disasm_panel(DisasmPanelConfig::new("Disasm", 0x1000));
        assert_eq!(api.open_panel_count(), 1);
        api.close_panel(&handle);
        assert_eq!(api.open_panel_count(), 0);
    }

    #[test]
    fn open_hex_panel() {
        let api = MockViewApi::new();
        let _ = api.open_hex_panel(HexPanelConfig::new("Hex", 0x2000));
        assert_eq!(api.open_panel_count(), 1);
    }

    #[test]
    fn open_graph_panel() {
        let api = MockViewApi::new();
        let _ = api.open_graph_panel(GraphConfig::control_flow("CFG", 0x1000));
        assert_eq!(api.open_panel_count(), 1);
    }

    #[test]
    fn menu_entry_handler_triggered() {
        let api = MockViewApi::new();
        let fired = Arc::new(Mutex::new(false));
        let fired2 = fired.clone();
        let entry = MenuEntry::new("test_action", "Do Test", MenuContext::DisasmView);
        api.add_menu_entry(entry, Box::new(move |_| { *fired2.lock().unwrap() = true; }));
        assert_eq!(api.menu_entry_count(), 1);
        api.trigger_menu("test_action", 0x1000);
        assert!(*fired.lock().unwrap());
    }

    #[test]
    fn menu_entry_removed() {
        let api = MockViewApi::new();
        let entry = MenuEntry::new("e1", "E1", MenuContext::HexView);
        api.add_menu_entry(entry, Box::new(|_| {}));
        api.remove_menu_entry("e1");
        assert_eq!(api.menu_entry_count(), 0);
    }

    #[test]
    fn toolbar_button_added() {
        let api = MockViewApi::new();
        let btn = ToolbarButton::new("btn1", "My Button");
        api.add_toolbar_button(btn, Box::new(|| {}));
        api.remove_toolbar_button("btn1");
    }

    #[test]
    fn keyboard_shortcut_registered() {
        let api = MockViewApi::new();
        let sc = KeyboardShortcut::global("find_all", Modifiers::CTRL, b'F' as u32);
        assert!(sc.display.contains("Ctrl"));
        api.register_shortcut(sc, Box::new(|| {}));
        assert_eq!(api.shortcut_count(), 1);
        api.unregister_shortcut("find_all");
        assert_eq!(api.shortcut_count(), 0);
    }

    #[test]
    fn notification_shown() {
        let api = MockViewApi::new();
        api.show_notification(Notification::info("Done", "Analysis finished"));
        api.show_notification(Notification::error("Error", "Something failed"));
        let notifs = api.notifications();
        assert_eq!(notifs.len(), 2);
        assert_eq!(notifs[0].level, NotificationLevel::Info);
        assert_eq!(notifs[1].level, NotificationLevel::Error);
    }

    #[test]
    fn highlights_set_and_cleared() {
        let api = MockViewApi::new();
        api.highlight_range(0x1000, 0x1010, 0xFF0000FF);
        api.highlight_range(0x2000, 0x2020, 0x00FF00FF);
        let hl = api.highlights.lock().unwrap();
        assert_eq!(hl.len(), 2);
        drop(hl);
        api.clear_highlights();
        assert!(api.highlights.lock().unwrap().is_empty());
    }

    #[test]
    fn panel_config_builder() {
        let cfg = PanelConfig::new("Test")
            .with_position(PanelPosition::Right)
            .with_size(1024, 768);
        assert_eq!(cfg.position, PanelPosition::Right);
        assert_eq!(cfg.width, 1024);
    }

    #[test]
    fn view_handle_display() {
        let h = ViewHandle::new(42);
        assert_eq!(h.to_string(), "view#42");
        assert_eq!(h.id(), 42);
    }

    #[test]
    fn modifiers_checks() {
        let m = Modifiers(Modifiers::CTRL.0 | Modifiers::SHIFT.0);
        assert!(m.has_ctrl());
        assert!(m.has_shift());
        assert!(!m.has_alt());
    }
}
