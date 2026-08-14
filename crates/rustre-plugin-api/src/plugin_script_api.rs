// rustre-plugin-api/src/plugin_script_api.rs
// High-level scripting API exposed to Lua/Python/Rhai scripts.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ─── Address / Range ─────────────────────────────────────────────────────────

/// A virtual address in the loaded binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptAddr(pub u64);

impl fmt::Display for ScriptAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// Half-open address range [start, end).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrRange {
    pub start: ScriptAddr,
    pub end: ScriptAddr,
}

impl AddrRange {
    #[must_use]
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start: ScriptAddr(start), end: ScriptAddr(end) }
    }

    #[must_use]
    pub fn contains(&self, addr: ScriptAddr) -> bool {
        addr >= self.start && addr < self.end
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── Binary Navigation ────────────────────────────────────────────────────────

/// A resolved symbol as seen from a script.
#[derive(Debug, Clone)]
pub struct ScriptSymbol {
    pub name: String,
    pub addr: ScriptAddr,
    pub size: u64,
    pub is_function: bool,
    pub is_imported: bool,
    pub is_exported: bool,
}

/// A function entry as seen from a script.
#[derive(Debug, Clone)]
pub struct ScriptFunction {
    pub name: Option<String>,
    pub start: ScriptAddr,
    pub end: ScriptAddr,
    pub instr_count: usize,
    pub basic_block_count: usize,
}

impl ScriptFunction {
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
}

/// A cross-reference from one address to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    DataRead,
    DataWrite,
    DataRef,
}

#[derive(Debug, Clone)]
pub struct Xref {
    pub from: ScriptAddr,
    pub to: ScriptAddr,
    pub kind: XrefKind,
}

/// Navigation API – enumerate and query binary entities.
pub struct BinaryNav {
    symbols: Arc<Mutex<Vec<ScriptSymbol>>>,
    functions: Arc<Mutex<Vec<ScriptFunction>>>,
    xrefs: Arc<Mutex<Vec<Xref>>>,
    bytes: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
}

impl BinaryNav {
    #[must_use]
    pub fn new() -> Self {
        Self {
            symbols: Arc::new(Mutex::new(Vec::new())),
            functions: Arc::new(Mutex::new(Vec::new())),
            xrefs: Arc::new(Mutex::new(Vec::new())),
            bytes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a symbol (called by the host).
    pub fn add_symbol(&self, sym: ScriptSymbol) {
        self.symbols.lock().unwrap().push(sym);
    }

    /// Register a function (called by the host).
    pub fn add_function(&self, func: ScriptFunction) {
        self.functions.lock().unwrap().push(func);
    }

    /// Load bytes into a memory region (called by the host).
    pub fn load_bytes(&self, base: u64, data: Vec<u8>) {
        self.bytes.lock().unwrap().insert(base, data);
    }

    /// Add a cross-reference.
    pub fn add_xref(&self, xref: Xref) {
        self.xrefs.lock().unwrap().push(xref);
    }

    /// Resolve a symbol by exact name.
    #[must_use]
    pub fn symbol_by_name(&self, name: &str) -> Option<ScriptSymbol> {
        self.symbols.lock().unwrap().iter().find(|s| s.name == name).cloned()
    }

    /// Find symbols whose name contains the given substring.
    #[must_use]
    pub fn symbols_containing(&self, substr: &str) -> Vec<ScriptSymbol> {
        self.symbols.lock().unwrap().iter()
            .filter(|s| s.name.contains(substr))
            .cloned()
            .collect()
    }

    /// Find all exported symbols.
    #[must_use]
    pub fn exports(&self) -> Vec<ScriptSymbol> {
        self.symbols.lock().unwrap().iter()
            .filter(|s| s.is_exported)
            .cloned()
            .collect()
    }

    /// Find all imported symbols.
    #[must_use]
    pub fn imports(&self) -> Vec<ScriptSymbol> {
        self.symbols.lock().unwrap().iter()
            .filter(|s| s.is_imported)
            .cloned()
            .collect()
    }

    /// Look up the function that contains the given address.
    #[must_use]
    pub fn function_at(&self, addr: ScriptAddr) -> Option<ScriptFunction> {
        self.functions.lock().unwrap().iter()
            .find(|f| addr >= f.start && addr < f.end)
            .cloned()
    }

    /// Return all known functions.
    #[must_use]
    pub fn all_functions(&self) -> Vec<ScriptFunction> {
        self.functions.lock().unwrap().clone()
    }

    /// Return functions whose name (if known) contains the substring.
    #[must_use]
    pub fn functions_named(&self, substr: &str) -> Vec<ScriptFunction> {
        self.functions.lock().unwrap().iter()
            .filter(|f| f.name.as_deref().unwrap_or("").contains(substr))
            .cloned()
            .collect()
    }

    /// Read bytes from the loaded memory map.
    #[must_use]
    pub fn read_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let map = self.bytes.lock().unwrap();
        for (base, data) in map.iter() {
            let base = *base;
            if addr >= base && addr + len as u64 <= base + data.len() as u64 {
                let off = (addr - base) as usize;
                return Some(data[off..off + len].to_vec());
            }
        }
        None
    }

    /// All callers of a given address.
    #[must_use]
    pub fn callers_of(&self, target: ScriptAddr) -> Vec<ScriptAddr> {
        self.xrefs.lock().unwrap().iter()
            .filter(|x| x.to == target && x.kind == XrefKind::Call)
            .map(|x| x.from)
            .collect()
    }

    /// All callees of a given caller address.
    #[must_use]
    pub fn callees_from(&self, caller: ScriptAddr) -> Vec<ScriptAddr> {
        self.xrefs.lock().unwrap().iter()
            .filter(|x| x.from == caller && x.kind == XrefKind::Call)
            .map(|x| x.to)
            .collect()
    }
}

impl Default for BinaryNav {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Annotation API ───────────────────────────────────────────────────────────

/// The severity / kind of an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationKind {
    Comment,
    Name,
    Tag,
    Highlight,
    Bookmark,
}

/// A single annotation placed by a script.
#[derive(Debug, Clone)]
pub struct Annotation {
    pub kind: AnnotationKind,
    pub addr: ScriptAddr,
    pub text: String,
    pub color: Option<u32>,   // ARGB
    pub author: String,
}

/// Commit / rollback for grouped annotation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Idle,
    Active,
    Committed,
    RolledBack,
}

/// API for adding comments, names, tags, and bookmarks.
pub struct AnnotationApi {
    annotations: Arc<Mutex<Vec<Annotation>>>,
    pending: Arc<Mutex<Vec<Annotation>>>,
    tx_state: Arc<Mutex<TransactionState>>,
    author: String,
}

impl AnnotationApi {
    #[must_use]
    pub fn new(author: impl Into<String>) -> Self {
        Self {
            annotations: Arc::new(Mutex::new(Vec::new())),
            pending: Arc::new(Mutex::new(Vec::new())),
            tx_state: Arc::new(Mutex::new(TransactionState::Idle)),
            author: author.into(),
        }
    }

    fn push_annot(&self, annot: Annotation) {
        let state = *self.tx_state.lock().unwrap();
        match state {
            TransactionState::Active => {
                self.pending.lock().unwrap().push(annot);
            }
            _ => {
                self.annotations.lock().unwrap().push(annot);
            }
        }
    }

    /// Add a comment at an address.
    pub fn comment(&self, addr: u64, text: impl Into<String>) {
        self.push_annot(Annotation {
            kind: AnnotationKind::Comment,
            addr: ScriptAddr(addr),
            text: text.into(),
            color: None,
            author: self.author.clone(),
        });
    }

    /// Rename the symbol / function at an address.
    pub fn rename(&self, addr: u64, name: impl Into<String>) {
        self.push_annot(Annotation {
            kind: AnnotationKind::Name,
            addr: ScriptAddr(addr),
            text: name.into(),
            color: None,
            author: self.author.clone(),
        });
    }

    /// Add a tag (free-form label) at an address.
    pub fn tag(&self, addr: u64, tag: impl Into<String>) {
        self.push_annot(Annotation {
            kind: AnnotationKind::Tag,
            addr: ScriptAddr(addr),
            text: tag.into(),
            color: None,
            author: self.author.clone(),
        });
    }

    /// Highlight an address with an ARGB color.
    pub fn highlight(&self, addr: u64, color: u32) {
        self.push_annot(Annotation {
            kind: AnnotationKind::Highlight,
            addr: ScriptAddr(addr),
            text: String::new(),
            color: Some(color),
            author: self.author.clone(),
        });
    }

    /// Place a bookmark.
    pub fn bookmark(&self, addr: u64, label: impl Into<String>) {
        self.push_annot(Annotation {
            kind: AnnotationKind::Bookmark,
            addr: ScriptAddr(addr),
            text: label.into(),
            color: None,
            author: self.author.clone(),
        });
    }

    /// Begin a transaction; subsequent annotations are buffered.
    pub fn begin_transaction(&self) {
        *self.tx_state.lock().unwrap() = TransactionState::Active;
    }

    /// Commit buffered annotations to the main list.
    pub fn commit(&self) {
        let mut pending = self.pending.lock().unwrap();
        let mut annotations = self.annotations.lock().unwrap();
        annotations.extend(pending.drain(..));
        *self.tx_state.lock().unwrap() = TransactionState::Committed;
    }

    /// Discard buffered annotations.
    pub fn rollback(&self) {
        self.pending.lock().unwrap().clear();
        *self.tx_state.lock().unwrap() = TransactionState::RolledBack;
    }

    /// Return all committed annotations at the given address.
    #[must_use]
    pub fn annotations_at(&self, addr: u64) -> Vec<Annotation> {
        self.annotations.lock().unwrap().iter()
            .filter(|a| a.addr.0 == addr)
            .cloned()
            .collect()
    }

    /// Return all annotations of a given kind.
    #[must_use]
    pub fn annotations_of_kind(&self, kind: AnnotationKind) -> Vec<Annotation> {
        self.annotations.lock().unwrap().iter()
            .filter(|a| a.kind == kind)
            .cloned()
            .collect()
    }

    /// Total committed annotation count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.annotations.lock().unwrap().len()
    }
}

// ─── Analysis API ─────────────────────────────────────────────────────────────

/// The kind of analysis a script can request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisKind {
    FunctionDiscovery,
    StringRecovery,
    CrossReferenceRebuild,
    TypeRecovery,
    ControlFlowGraph { func_addr: u64 },
    DataFlowForward { start: u64 },
    DataFlowBackward { start: u64 },
    Custom(String),
}

/// Completion status of an analysis request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// A handle returned when analysis is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnalysisHandle(u64);

/// A pending or completed analysis entry.
#[derive(Debug, Clone)]
pub struct AnalysisEntry {
    pub handle: AnalysisHandle,
    pub kind: AnalysisKind,
    pub status: AnalysisStatus,
    pub progress: f32,
    pub error_msg: Option<String>,
}

/// Script-facing API for triggering and monitoring analysis passes.
pub struct AnalysisApi {
    next_id: Arc<Mutex<u64>>,
    entries: Arc<Mutex<Vec<AnalysisEntry>>>,
}

impl AnalysisApi {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: Arc::new(Mutex::new(1)),
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn alloc_id(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap();
        let current = *id;
        *id += 1;
        current
    }

    /// Request an analysis pass; returns a handle to track completion.
    #[must_use] 
    pub fn request(&self, kind: AnalysisKind) -> AnalysisHandle {
        let handle = AnalysisHandle(self.alloc_id());
        self.entries.lock().unwrap().push(AnalysisEntry {
            handle,
            kind,
            status: AnalysisStatus::Queued,
            progress: 0.0,
            error_msg: None,
        });
        handle
    }

    /// Query the status of a previously requested analysis.
    #[must_use]
    pub fn status(&self, handle: AnalysisHandle) -> Option<AnalysisStatus> {
        self.entries.lock().unwrap().iter()
            .find(|e| e.handle == handle)
            .map(|e| e.status)
    }

    /// Advance status (called by the host/executor).
    pub fn set_status(&self, handle: AnalysisHandle, status: AnalysisStatus, progress: f32) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.handle == handle) {
            e.status = status;
            e.progress = progress.clamp(0.0, 1.0);
        }
    }

    /// Mark an analysis as failed with an error message.
    pub fn set_failed(&self, handle: AnalysisHandle, msg: impl Into<String>) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.handle == handle) {
            e.status = AnalysisStatus::Failed;
            e.error_msg = Some(msg.into());
        }
    }

    /// Cancel a queued/running analysis.
    #[must_use] 
    pub fn cancel(&self, handle: AnalysisHandle) -> bool {
        let mut entries = self.entries.lock().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.handle == handle)
            && matches!(e.status, AnalysisStatus::Queued | AnalysisStatus::Running) {
                e.status = AnalysisStatus::Cancelled;
                return true;
            }
        false
    }

    /// Return all entries whose status matches.
    #[must_use]
    pub fn entries_with_status(&self, status: AnalysisStatus) -> Vec<AnalysisEntry> {
        self.entries.lock().unwrap().iter()
            .filter(|e| e.status == status)
            .cloned()
            .collect()
    }

    /// How many analyses are currently queued or running.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.entries.lock().unwrap().iter()
            .filter(|e| matches!(e.status, AnalysisStatus::Queued | AnalysisStatus::Running))
            .count()
    }
}

impl Default for AnalysisApi {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Result Collector ─────────────────────────────────────────────────────────

/// The value of a single script result entry.
#[derive(Debug, Clone)]
pub enum ScriptValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Addr(ScriptAddr),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Map(HashMap<String, Self>),
}

impl fmt::Display for ScriptValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Addr(a) => write!(f, "{a}"),
            Self::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            Self::List(l) => write!(f, "[{} items]", l.len()),
            Self::Map(m) => write!(f, "{{{} keys}}", m.len()),
        }
    }
}

/// A single row in the result collector table.
#[derive(Debug, Clone)]
pub struct ResultRow {
    pub addr: Option<ScriptAddr>,
    pub label: String,
    pub fields: HashMap<String, ScriptValue>,
}

impl ResultRow {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self { addr: None, label: label.into(), fields: HashMap::new() }
    }

    #[must_use] 
    pub const fn with_addr(mut self, addr: u64) -> Self {
        self.addr = Some(ScriptAddr(addr));
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: ScriptValue) -> Self {
        self.fields.insert(key.into(), value);
        self
    }
}

/// Collects rows and key/value metadata produced by a script run.
pub struct ResultCollector {
    rows: Arc<Mutex<Vec<ResultRow>>>,
    metadata: Arc<Mutex<HashMap<String, ScriptValue>>>,
    errors: Arc<Mutex<Vec<String>>>,
    warnings: Arc<Mutex<Vec<String>>>,
}

impl ResultCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: Arc::new(Mutex::new(Vec::new())),
            metadata: Arc::new(Mutex::new(HashMap::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            warnings: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a result row.
    pub fn add_row(&self, row: ResultRow) {
        self.rows.lock().unwrap().push(row);
    }

    /// Convenience: add a simple address + label row.
    pub fn add_addr(&self, addr: u64, label: impl Into<String>) {
        self.add_row(ResultRow::new(label).with_addr(addr));
    }

    /// Set a global metadata key.
    pub fn set_meta(&self, key: impl Into<String>, value: ScriptValue) {
        self.metadata.lock().unwrap().insert(key.into(), value);
    }

    /// Record a script error.
    pub fn error(&self, msg: impl Into<String>) {
        self.errors.lock().unwrap().push(msg.into());
    }

    /// Record a script warning.
    pub fn warn(&self, msg: impl Into<String>) {
        self.warnings.lock().unwrap().push(msg.into());
    }

    /// All collected rows.
    #[must_use]
    pub fn rows(&self) -> Vec<ResultRow> {
        self.rows.lock().unwrap().clone()
    }

    /// All metadata entries.
    #[must_use]
    pub fn metadata(&self) -> HashMap<String, ScriptValue> {
        self.metadata.lock().unwrap().clone()
    }

    /// All recorded errors.
    #[must_use]
    pub fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().clone()
    }

    /// All recorded warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        self.warnings.lock().unwrap().clone()
    }

    /// True if no errors were recorded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.lock().unwrap().is_empty()
    }

    /// Drain all rows (consumes them from the collector).
    #[must_use] 
    pub fn drain_rows(&self) -> Vec<ResultRow> {
        self.rows.lock().unwrap().drain(..).collect()
    }
}

impl Default for ResultCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ScriptApi facade ─────────────────────────────────────────────────────────

/// The top-level facade that a script engine receives.
/// Provides access to navigation, annotation, analysis, and result collection.
pub struct ScriptApi {
    pub nav: Arc<BinaryNav>,
    pub annot: Arc<AnnotationApi>,
    pub analysis: Arc<AnalysisApi>,
    pub results: Arc<ResultCollector>,
    script_name: String,
    script_language: ScriptLanguage,
}

/// The scripting language/engine being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLanguage {
    Lua,
    Python,
    Rhai,
    Javascript,
    Unknown,
}

impl fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lua => write!(f, "Lua"),
            Self::Python => write!(f, "Python"),
            Self::Rhai => write!(f, "Rhai"),
            Self::Javascript => write!(f, "JavaScript"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl ScriptApi {
    #[must_use]
    pub fn new(script_name: impl Into<String>, lang: ScriptLanguage) -> Self {
        let name = script_name.into();
        Self {
            nav: Arc::new(BinaryNav::new()),
            annot: Arc::new(AnnotationApi::new(&name)),
            analysis: Arc::new(AnalysisApi::new()),
            results: Arc::new(ResultCollector::new()),
            script_name: name,
            script_language: lang,
        }
    }

    #[must_use]
    pub fn script_name(&self) -> &str {
        &self.script_name
    }

    #[must_use]
    pub const fn language(&self) -> ScriptLanguage {
        self.script_language
    }

    /// Short summary for logging / display.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] lang={} rows={} errors={}",
            self.script_name,
            self.script_language,
            self.results.rows.lock().unwrap().len(),
            self.results.errors.lock().unwrap().len(),
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_nav_symbol_lookup() {
        let nav = BinaryNav::new();
        nav.add_symbol(ScriptSymbol {
            name: "CreateFileW".into(),
            addr: ScriptAddr(0x1000),
            size: 0,
            is_function: true,
            is_imported: true,
            is_exported: false,
        });
        let sym = nav.symbol_by_name("CreateFileW").unwrap();
        assert_eq!(sym.addr.0, 0x1000);
        assert!(sym.is_imported);
    }

    #[test]
    fn test_binary_nav_function_at() {
        let nav = BinaryNav::new();
        nav.add_function(ScriptFunction {
            name: Some("sub_1234".into()),
            start: ScriptAddr(0x1234),
            end: ScriptAddr(0x1260),
            instr_count: 20,
            basic_block_count: 3,
        });
        assert!(nav.function_at(ScriptAddr(0x1240)).is_some());
        assert!(nav.function_at(ScriptAddr(0x1260)).is_none());
    }

    #[test]
    fn test_binary_nav_read_bytes() {
        let nav = BinaryNav::new();
        nav.load_bytes(0x2000, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let b = nav.read_bytes(0x2001, 2).unwrap();
        assert_eq!(b, &[0xBB, 0xCC]);
        assert!(nav.read_bytes(0x1000, 1).is_none());
    }

    #[test]
    fn test_annotation_commit_rollback() {
        let api = AnnotationApi::new("test_author");
        api.comment(0x1000, "initial");
        assert_eq!(api.count(), 1);

        api.begin_transaction();
        api.rename(0x2000, "renamed_fn");
        api.tag(0x3000, "suspect");
        assert_eq!(api.count(), 1);  // not yet committed

        api.rollback();
        assert_eq!(api.count(), 1);  // discard the two pending

        api.begin_transaction();
        api.bookmark(0x4000, "interesting");
        api.commit();
        assert_eq!(api.count(), 2);
    }

    #[test]
    fn test_annotation_highlight() {
        let api = AnnotationApi::new("tester");
        api.highlight(0x5000, 0xFF_FF_00_00);
        let annots = api.annotations_of_kind(AnnotationKind::Highlight);
        assert_eq!(annots.len(), 1);
        assert_eq!(annots[0].color, Some(0xFF_FF_00_00));
    }

    #[test]
    fn test_analysis_api_lifecycle() {
        let api = AnalysisApi::new();
        let h = api.request(AnalysisKind::FunctionDiscovery);
        assert_eq!(api.status(h), Some(AnalysisStatus::Queued));
        assert_eq!(api.pending_count(), 1);

        api.set_status(h, AnalysisStatus::Running, 0.5);
        assert_eq!(api.status(h), Some(AnalysisStatus::Running));

        api.set_status(h, AnalysisStatus::Completed, 1.0);
        assert_eq!(api.pending_count(), 0);
    }

    #[test]
    fn test_analysis_cancel() {
        let api = AnalysisApi::new();
        let h = api.request(AnalysisKind::StringRecovery);
        assert!(api.cancel(h));
        assert_eq!(api.status(h), Some(AnalysisStatus::Cancelled));
        assert!(!api.cancel(h));  // already cancelled
    }

    #[test]
    fn test_result_collector_rows() {
        let col = ResultCollector::new();
        col.add_addr(0xDEAD, "suspicious");
        col.add_row(
            ResultRow::new("data_ref")
                .with_addr(0xBEEF)
                .field("size", ScriptValue::Int(128))
                .field("name", ScriptValue::Str("buf".into())),
        );
        assert_eq!(col.rows().len(), 2);
        assert!(col.is_ok());
    }

    #[test]
    fn test_result_collector_errors() {
        let col = ResultCollector::new();
        col.error("undefined symbol at 0x1000");
        col.warn("heuristic fallback used");
        assert!(!col.is_ok());
        assert_eq!(col.errors().len(), 1);
        assert_eq!(col.warnings().len(), 1);
    }

    #[test]
    fn test_result_drain() {
        let col = ResultCollector::new();
        col.add_addr(0x1, "a");
        col.add_addr(0x2, "b");
        let drained = col.drain_rows();
        assert_eq!(drained.len(), 2);
        assert_eq!(col.rows().len(), 0);
    }

    #[test]
    fn test_script_api_summary() {
        let api = ScriptApi::new("find_crypto", ScriptLanguage::Python);
        api.results.add_addr(0x1000, "AES_key_schedule");
        let summary = api.summary();
        assert!(summary.contains("find_crypto"));
        assert!(summary.contains("Python"));
        assert!(summary.contains("rows=1"));
    }

    #[test]
    fn test_addr_range() {
        let r = AddrRange::new(0x1000, 0x2000);
        assert!(r.contains(ScriptAddr(0x1500)));
        assert!(!r.contains(ScriptAddr(0x2000)));
        assert_eq!(r.len(), 0x1000);
    }

    #[test]
    fn test_xref_callers() {
        let nav = BinaryNav::new();
        nav.add_xref(Xref { from: ScriptAddr(0x100), to: ScriptAddr(0x500), kind: XrefKind::Call });
        nav.add_xref(Xref { from: ScriptAddr(0x200), to: ScriptAddr(0x500), kind: XrefKind::Call });
        nav.add_xref(Xref { from: ScriptAddr(0x300), to: ScriptAddr(0x500), kind: XrefKind::Jump });
        let callers = nav.callers_of(ScriptAddr(0x500));
        assert_eq!(callers.len(), 2);
    }

    #[test]
    fn test_script_value_display() {
        assert_eq!(format!("{}", ScriptValue::Null), "null");
        assert_eq!(format!("{}", ScriptValue::Bool(true)), "true");
        assert_eq!(format!("{}", ScriptValue::Int(-42)), "-42");
        assert_eq!(format!("{}", ScriptValue::Addr(ScriptAddr(0xFF))),
            "0x00000000000000ff");
    }
}
