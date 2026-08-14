// rustre-plugin-api/src/plugin_context_api.rs
//
// Plugin context API: access to analysis context from a plugin. Provides
// queries over binary info, symbols, functions, strings, analysis pass
// requests, and event callbacks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// BinaryInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture of the loaded binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryArch {
    X86_64,
    X86_32,
    Arm64,
    Arm32,
    Mips32,
    Mips64,
    PowerPc32,
    PowerPc64,
    RiscV32,
    RiscV64,
    Unknown(String),
}

impl BinaryArch {
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::X86_64    => "x86_64",
            Self::X86_32    => "x86_32",
            Self::Arm64     => "aarch64",
            Self::Arm32     => "arm32",
            Self::Mips32    => "mips32",
            Self::Mips64    => "mips64",
            Self::PowerPc32 => "ppc32",
            Self::PowerPc64 => "ppc64",
            Self::RiscV32   => "riscv32",
            Self::RiscV64   => "riscv64",
            Self::Unknown(s) => s.as_str(),
        }
    }

    #[must_use]
    pub const fn address_size(&self) -> usize {
        match self {
            Self::X86_64 | Self::Arm64 | Self::Mips64 | Self::PowerPc64 | Self::RiscV64 => 8,
            _ => 4,
        }
    }
}

/// Operating system / platform the binary targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryOs {
    Windows,
    Linux,
    MacOs,
    Ios,
    Android,
    FreeBsd,
    Uefi,
    Bare,
    Unknown(String),
}

impl BinaryOs {
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Windows  => "windows",
            Self::Linux    => "linux",
            Self::MacOs    => "macos",
            Self::Ios      => "ios",
            Self::Android  => "android",
            Self::FreeBsd  => "freebsd",
            Self::Uefi     => "uefi",
            Self::Bare     => "bare",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// High-level description of a loaded binary.
#[derive(Debug, Clone)]
pub struct BinaryInfo {
    /// Path or identifier of the loaded file.
    pub path: String,
    /// Target architecture.
    pub arch: BinaryArch,
    /// Target operating system.
    pub os: BinaryOs,
    /// Preferred image base.
    pub base_address: u64,
    /// Entry-point virtual address.
    pub entry_point: u64,
    /// Total size of the mapped image in bytes.
    pub image_size: u64,
    /// Whether the binary is position-independent.
    pub is_pie: bool,
    /// Whether the binary is a DLL / shared object.
    pub is_dll: bool,
    /// File format (PE, ELF, `MachO`, raw, …).
    pub format: String,
    /// Endianness: `true` = little-endian.
    pub little_endian: bool,
}

impl BinaryInfo {
    /// Create a minimal placeholder binary info.
    #[must_use]
    pub fn placeholder() -> Self {
        Self {
            path: String::from("<unknown>"),
            arch: BinaryArch::Unknown(String::from("?")),
            os: BinaryOs::Unknown(String::from("?")),
            base_address: 0,
            entry_point: 0,
            image_size: 0,
            is_pie: false,
            is_dll: false,
            format: String::from("raw"),
            little_endian: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbol / Function / String records exposed to plugins
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of symbol visible to a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Label,
    External,
    Unknown,
}

/// A symbol record returned by the context API.
#[derive(Debug, Clone)]
pub struct ContextSymbol {
    pub address: u64,
    pub name: String,
    pub kind: SymbolKind,
    pub size: Option<u64>,
    pub is_external: bool,
}

impl ContextSymbol {
    #[must_use]
    pub fn function(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            kind: SymbolKind::Function,
            size: None,
            is_external: false,
        }
    }
}

/// A function record exposed to plugins.
#[derive(Debug, Clone)]
pub struct ContextFunction {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub arch: String,
    pub tags: Vec<String>,
    pub is_thunk: bool,
    pub is_imported: bool,
    pub calling_convention: String,
}

impl ContextFunction {
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>, size: u64) -> Self {
        Self {
            address,
            name: name.into(),
            size,
            arch: String::new(),
            tags: Vec::new(),
            is_thunk: false,
            is_imported: false,
            calling_convention: String::from("unknown"),
        }
    }
}

/// A string reference returned by the context API.
#[derive(Debug, Clone)]
pub struct ContextString {
    pub address: u64,
    pub value: String,
    pub encoding: StringEncoding,
    pub length: usize,
}

/// String encoding kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisRequest
// ─────────────────────────────────────────────────────────────────────────────

/// Request to run an analysis pass from within a plugin.
#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    /// Name of the analysis pass to run.
    pub pass_name: String,
    /// Optional target function address (run only on one function).
    pub function_addr: Option<u64>,
    /// Additional key-value parameters for the pass.
    pub params: HashMap<String, String>,
    /// Priority hint: higher runs first.
    pub priority: i32,
}

impl AnalysisRequest {
    /// Create a full-binary analysis request.
    #[must_use]
    pub fn full_binary(pass_name: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            function_addr: None,
            params: HashMap::new(),
            priority: 0,
        }
    }

    /// Create a single-function analysis request.
    #[must_use]
    pub fn for_function(pass_name: impl Into<String>, addr: u64) -> Self {
        Self {
            pass_name: pass_name.into(),
            function_addr: Some(addr),
            params: HashMap::new(),
            priority: 0,
        }
    }

    /// Add a parameter.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.params.insert(key.into(), val.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginCallback
// ─────────────────────────────────────────────────────────────────────────────

/// Type of analysis event a plugin can subscribe to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnalysisEvent {
    FunctionAdded,
    FunctionRemoved,
    FunctionRenamed,
    DataDefined,
    StringFound,
    AnalysisStarted,
    AnalysisFinished,
    BinaryOpened,
    Custom(String),
}

impl AnalysisEvent {
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::FunctionAdded   => "function_added",
            Self::FunctionRemoved => "function_removed",
            Self::FunctionRenamed => "function_renamed",
            Self::DataDefined     => "data_defined",
            Self::StringFound     => "string_found",
            Self::AnalysisStarted => "analysis_started",
            Self::AnalysisFinished => "analysis_finished",
            Self::BinaryOpened    => "binary_opened",
            Self::Custom(s)       => s.as_str(),
        }
    }
}

/// Payload delivered to an analysis event callback.
#[derive(Debug, Clone)]
pub struct EventPayload {
    pub event: AnalysisEvent,
    pub address: Option<u64>,
    pub name: Option<String>,
    pub extra: HashMap<String, String>,
}

impl EventPayload {
    #[must_use]
    pub fn simple(event: AnalysisEvent) -> Self {
        Self { event, address: None, name: None, extra: HashMap::new() }
    }
}

/// A registered callback for analysis events.
pub struct PluginCallback {
    pub id: u64,
    pub event: AnalysisEvent,
    pub handler: Box<dyn Fn(&EventPayload) + Send + Sync + 'static>,
}

impl std::fmt::Debug for PluginCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PluginCallback {{ id: {}, event: {:?} }}", self.id, self.event)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextAccess — trait defining what a plugin can ask of the host
// ─────────────────────────────────────────────────────────────────────────────

/// Trait providing read-only access to the host analysis context.
pub trait ContextAccess: Send + Sync {
    /// Return basic information about the loaded binary.
    fn binary_info(&self) -> BinaryInfo;

    /// Look up a symbol by virtual address.
    fn symbol_at(&self, addr: u64) -> Option<ContextSymbol>;

    /// Return all symbols whose names contain `filter`.
    fn symbols_matching(&self, filter: &str) -> Vec<ContextSymbol>;

    /// Return all known functions.
    fn all_functions(&self) -> Vec<ContextFunction>;

    /// Look up a single function by address.
    fn function_at(&self, addr: u64) -> Option<ContextFunction>;

    /// Return all detected strings, filtered by minimum length.
    fn strings(&self, min_length: usize) -> Vec<ContextString>;

    /// Read raw bytes from the binary image at `addr`.
    fn read_bytes(&self, addr: u64, count: usize) -> Option<Vec<u8>>;

    /// Queue an analysis pass to run.
    fn request_analysis(&self, request: AnalysisRequest);

    /// Register a callback for a specific analysis event.
    /// Returns a callback ID that can be used to unregister.
    fn register_callback(
        &self,
        event: AnalysisEvent,
        handler: Box<dyn Fn(&EventPayload) + Send + Sync + 'static>,
    ) -> u64;

    /// Remove a previously registered callback.
    fn unregister_callback(&self, id: u64);
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginContext — concrete implementation backed by in-memory state
// ─────────────────────────────────────────────────────────────────────────────

/// Concrete in-memory implementation of [`ContextAccess`] for testing and stubs.
pub struct PluginContext {
    info: BinaryInfo,
    symbols: Vec<ContextSymbol>,
    functions: Vec<ContextFunction>,
    strings: Vec<ContextString>,
    memory: HashMap<u64, Vec<u8>>,
    pending_requests: Arc<Mutex<Vec<AnalysisRequest>>>,
    callbacks: Arc<Mutex<Vec<PluginCallback>>>,
    next_callback_id: Arc<Mutex<u64>>,
}

impl PluginContext {
    /// Create a new plugin context with the given binary info.
    #[must_use]
    pub fn new(info: BinaryInfo) -> Self {
        Self {
            info,
            symbols: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            memory: HashMap::new(),
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            next_callback_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Add a symbol to the context.
    pub fn add_symbol(&mut self, sym: ContextSymbol) {
        self.symbols.push(sym);
    }

    /// Add a function record.
    pub fn add_function(&mut self, func: ContextFunction) {
        self.functions.push(func);
    }

    /// Add a string record.
    pub fn add_string(&mut self, s: ContextString) {
        self.strings.push(s);
    }

    /// Map raw bytes at a virtual address.
    pub fn map_bytes(&mut self, addr: u64, bytes: Vec<u8>) {
        self.memory.insert(addr, bytes);
    }

    /// Drain all queued analysis requests.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn drain_requests(&self) -> Vec<AnalysisRequest> {
        self.pending_requests.lock().unwrap().drain(..).collect()
    }

    /// Dispatch a payload to all matching callbacks.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn dispatch_event(&self, payload: &EventPayload) {
        let cbs = self.callbacks.lock().unwrap();
        for cb in cbs.iter() {
            if cb.event == payload.event {
                (cb.handler)(payload);
            }
        }
    }

    /// Count of registered callbacks.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn callback_count(&self) -> usize {
        self.callbacks.lock().unwrap().len()
    }
}

impl ContextAccess for PluginContext {
    fn binary_info(&self) -> BinaryInfo {
        self.info.clone()
    }

    fn symbol_at(&self, addr: u64) -> Option<ContextSymbol> {
        self.symbols.iter().find(|s| s.address == addr).cloned()
    }

    fn symbols_matching(&self, filter: &str) -> Vec<ContextSymbol> {
        self.symbols.iter()
            .filter(|s| s.name.contains(filter))
            .cloned()
            .collect()
    }

    fn all_functions(&self) -> Vec<ContextFunction> {
        self.functions.clone()
    }

    fn function_at(&self, addr: u64) -> Option<ContextFunction> {
        self.functions.iter().find(|f| f.address == addr).cloned()
    }

    fn strings(&self, min_length: usize) -> Vec<ContextString> {
        self.strings.iter()
            .filter(|s| s.length >= min_length)
            .cloned()
            .collect()
    }

    fn read_bytes(&self, addr: u64, count: usize) -> Option<Vec<u8>> {
        // Search for the mapping that covers [addr, addr+count)
        for (&base, bytes) in &self.memory {
            if addr >= base && addr + count as u64 <= base + bytes.len() as u64 {
                let off = (addr - base) as usize;
                return Some(bytes[off..off + count].to_vec());
            }
        }
        None
    }

    fn request_analysis(&self, request: AnalysisRequest) {
        self.pending_requests.lock().unwrap().push(request);
    }

    fn register_callback(
        &self,
        event: AnalysisEvent,
        handler: Box<dyn Fn(&EventPayload) + Send + Sync + 'static>,
    ) -> u64 {
        let mut next = self.next_callback_id.lock().unwrap();
        let id = *next;
        *next += 1;
        drop(next);
        self.callbacks.lock().unwrap().push(PluginCallback { id, event, handler });
        id
    }

    fn unregister_callback(&self, id: u64) {
        self.callbacks.lock().unwrap().retain(|cb| cb.id != id);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Query all functions containing the substring `name_fragment` in their name.
#[must_use]
pub fn find_functions_by_name<C: ContextAccess>(ctx: &C, name_fragment: &str) -> Vec<ContextFunction> {
    ctx.all_functions().into_iter()
        .filter(|f| f.name.contains(name_fragment))
        .collect()
}

/// Find all strings that look like URLs.
#[must_use]
pub fn find_url_strings<C: ContextAccess>(ctx: &C) -> Vec<ContextString> {
    ctx.strings(7).into_iter()
        .filter(|s| s.value.starts_with("http://") || s.value.starts_with("https://"))
        .collect()
}

/// Find all strings that contain a file path separator.
#[must_use]
pub fn find_path_strings<C: ContextAccess>(ctx: &C) -> Vec<ContextString> {
    ctx.strings(3).into_iter()
        .filter(|s| s.value.contains('/') || s.value.contains('\\'))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> PluginContext {
        let info = BinaryInfo {
            path: "/tmp/test.exe".into(),
            arch: BinaryArch::X86_64,
            os: BinaryOs::Windows,
            base_address: 0x0000_0001_4000_0000,
            entry_point: 0x0000_0001_4001_0000,
            image_size: 0x10_0000,
            is_pie: false,
            is_dll: false,
            format: "PE".into(),
            little_endian: true,
        };
        PluginContext::new(info)
    }

    #[test]
    fn binary_info_round_trip() {
        let ctx = make_ctx();
        let info = ctx.binary_info();
        assert_eq!(info.arch, BinaryArch::X86_64);
        assert_eq!(info.os, BinaryOs::Windows);
        assert_eq!(info.arch.address_size(), 8);
    }

    #[test]
    fn symbol_at_found() {
        let mut ctx = make_ctx();
        ctx.add_symbol(ContextSymbol::function(0x1000, "main"));
        assert!(ctx.symbol_at(0x1000).is_some());
        assert!(ctx.symbol_at(0x2000).is_none());
    }

    #[test]
    fn symbols_matching_filter() {
        let mut ctx = make_ctx();
        ctx.add_symbol(ContextSymbol::function(0x1000, "malloc"));
        ctx.add_symbol(ContextSymbol::function(0x2000, "realloc"));
        ctx.add_symbol(ContextSymbol::function(0x3000, "free"));
        let results = ctx.symbols_matching("alloc");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn all_functions_and_function_at() {
        let mut ctx = make_ctx();
        ctx.add_function(ContextFunction::new(0x1000, "foo", 0x40));
        ctx.add_function(ContextFunction::new(0x2000, "bar", 0x80));
        assert_eq!(ctx.all_functions().len(), 2);
        assert!(ctx.function_at(0x1000).is_some());
        assert!(ctx.function_at(0x9999).is_none());
    }

    #[test]
    fn strings_min_length_filter() {
        let mut ctx = make_ctx();
        ctx.add_string(ContextString {
            address: 0x4000, value: "hi".into(), encoding: StringEncoding::Ascii, length: 2,
        });
        ctx.add_string(ContextString {
            address: 0x4010, value: "hello world".into(), encoding: StringEncoding::Ascii, length: 11,
        });
        assert_eq!(ctx.strings(5).len(), 1);
    }

    #[test]
    fn read_bytes_within_range() {
        let mut ctx = make_ctx();
        ctx.map_bytes(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let bytes = ctx.read_bytes(0x1001, 2).unwrap();
        assert_eq!(bytes, [0xBB, 0xCC]);
    }

    #[test]
    fn read_bytes_out_of_range_returns_none() {
        let ctx = make_ctx();
        assert!(ctx.read_bytes(0x9999, 4).is_none());
    }

    #[test]
    fn analysis_request_queued() {
        let ctx = make_ctx();
        ctx.request_analysis(AnalysisRequest::full_binary("type_recovery"));
        let requests = ctx.drain_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].pass_name, "type_recovery");
    }

    #[test]
    fn callback_registered_and_fired() {
        let ctx = make_ctx();
        let fired = Arc::new(Mutex::new(false));
        let fired2 = fired.clone();
        ctx.register_callback(
            AnalysisEvent::FunctionAdded,
            Box::new(move |_| { *fired2.lock().unwrap() = true; }),
        );
        ctx.dispatch_event(&EventPayload::simple(AnalysisEvent::FunctionAdded));
        assert!(*fired.lock().unwrap());
    }

    #[test]
    fn callback_unregistered() {
        let ctx = make_ctx();
        let count = Arc::new(Mutex::new(0u32));
        let c2 = count.clone();
        let id = ctx.register_callback(
            AnalysisEvent::FunctionAdded,
            Box::new(move |_| { *c2.lock().unwrap() += 1; }),
        );
        ctx.unregister_callback(id);
        ctx.dispatch_event(&EventPayload::simple(AnalysisEvent::FunctionAdded));
        assert_eq!(*count.lock().unwrap(), 0);
    }

    #[test]
    fn find_url_strings_helper() {
        let mut ctx = make_ctx();
        ctx.add_string(ContextString {
            address: 0x4000,
            value: "https://example.com".into(),
            encoding: StringEncoding::Ascii,
            length: 19,
        });
        ctx.add_string(ContextString {
            address: 0x4020,
            value: "C:\\Windows\\System32".into(),
            encoding: StringEncoding::Ascii,
            length: 19,
        });
        let urls = find_url_strings(&ctx);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn binary_arch_address_size() {
        assert_eq!(BinaryArch::X86_32.address_size(), 4);
        assert_eq!(BinaryArch::Arm64.address_size(), 8);
    }
}
