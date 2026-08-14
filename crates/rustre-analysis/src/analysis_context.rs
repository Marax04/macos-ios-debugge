/// Analysis context — unified state container for all analysis passes.
///
/// [`AnalysisCtx`] holds every piece of information derived from a binary:
/// functions, strings, cross-references and progress tracking.  It is
/// designed to be built incrementally by successive [`AnalysisPass`]
/// implementations and then queried by higher-level consumers.
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ── Address ───────────────────────────────────────────────────────────────────

/// Virtual address within the analysed binary.
pub type Addr = u64;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtxError {
    /// The address is not mapped.
    UnmappedAddress(Addr),
    /// A function with that address already exists.
    DuplicateFunction(Addr),
    /// A string with that address already exists.
    DuplicateString(Addr),
    /// Attempted to modify a frozen context.
    Frozen,
    /// A required field was not set.
    MissingField(&'static str),
}

impl fmt::Display for CtxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmappedAddress(a) => write!(f, "unmapped address 0x{a:x}"),
            Self::DuplicateFunction(a) => write!(f, "duplicate function at 0x{a:x}"),
            Self::DuplicateString(a) => write!(f, "duplicate string at 0x{a:x}"),
            Self::Frozen => write!(f, "context is frozen"),
            Self::MissingField(n) => write!(f, "missing field: {n}"),
        }
    }
}

pub type CtxResult<T> = Result<T, CtxError>;

// ── FunctionInfo ─────────────────────────────────────────────────────────────

/// All information known about a single function.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Start address.
    pub start: Addr,
    /// Byte length (0 = unknown).
    pub length: u64,
    /// Human-readable name (mangled or demangled).
    pub name: Option<String>,
    /// True if this function was identified by a reliable symbol.
    pub has_symbol: bool,
    /// True if the function appears to return a value.
    pub returns_value: bool,
    /// Number of basic blocks identified.
    pub block_count: u32,
    /// Number of call sites within this function.
    pub call_count: u32,
    /// Arbitrary per-function annotations.
    pub tags: Vec<String>,
}

impl FunctionInfo {
    #[must_use]
    pub const fn new(start: Addr) -> Self {
        Self {
            start,
            length: 0,
            name: None,
            has_symbol: false,
            returns_value: true,
            block_count: 0,
            call_count: 0,
            tags: Vec::new(),
        }
    }

    /// Returns the name if set, otherwise a hex string.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", self.start))
    }

    /// Returns the end address (exclusive), or `start` if length is unknown.
    #[must_use]
    pub const fn end(&self) -> Addr {
        if self.length == 0 {
            self.start
        } else {
            self.start + self.length
        }
    }

    /// Returns `true` if `addr` lies within this function (requires length > 0).
    #[must_use]
    pub const fn contains(&self, addr: Addr) -> bool {
        self.length > 0 && addr >= self.start && addr < self.end()
    }

    /// Adds a tag if not already present.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }
}

// ── StringInfo ───────────────────────────────────────────────────────────────

/// The encoding of a string found in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    Unknown,
}

/// A string constant discovered in the binary.
#[derive(Debug, Clone)]
pub struct StringInfo {
    /// Address of the first byte.
    pub address: Addr,
    /// Raw bytes (without null terminator).
    pub value: String,
    /// Byte length including any null terminator.
    pub byte_length: usize,
    /// String encoding.
    pub encoding: StringEncoding,
    /// Section name this string lives in (e.g. `.rodata`).
    pub section: Option<String>,
}

impl StringInfo {
    #[must_use]
    pub fn new(address: Addr, value: impl Into<String>) -> Self {
        let value = value.into();
        let byte_length = value.len() + 1; // + null
        Self {
            address,
            value,
            byte_length,
            encoding: StringEncoding::Utf8,
            section: None,
        }
    }

    /// Returns `true` if the string contains any non-ASCII bytes.
    #[must_use]
    pub fn is_non_ascii(&self) -> bool {
        !self.value.is_ascii()
    }

    /// Returns `true` if the string looks like a Windows API name.
    #[must_use]
    pub fn looks_like_api(&self) -> bool {
        self.value.len() > 2
            && self.value.chars().next().is_some_and(char::is_uppercase)
            && self.value.chars().all(|c| c.is_alphanumeric() || c == '_')
    }
}

// ── XrefInfo ─────────────────────────────────────────────────────────────────

/// Kind of cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// A direct call instruction.
    Call,
    /// An indirect call through a register or memory.
    CallIndirect,
    /// An unconditional or conditional jump.
    Jump,
    /// A data reference (e.g. load/store of an address).
    Data,
    /// A string reference.
    StringRef,
}

/// One cross-reference edge.
#[derive(Debug, Clone)]
pub struct XrefInfo {
    /// Address of the instruction that makes the reference.
    pub from: Addr,
    /// Target address.
    pub to: Addr,
    /// Nature of the reference.
    pub kind: XrefKind,
}

impl XrefInfo {
    #[must_use]
    pub const fn call(from: Addr, to: Addr) -> Self {
        Self { from, to, kind: XrefKind::Call }
    }

    #[must_use]
    pub const fn jump(from: Addr, to: Addr) -> Self {
        Self { from, to, kind: XrefKind::Jump }
    }

    #[must_use]
    pub const fn data(from: Addr, to: Addr) -> Self {
        Self { from, to, kind: XrefKind::Data }
    }
}

// ── AnalysisProgress ─────────────────────────────────────────────────────────

/// Tracks which analysis passes have been completed.
#[derive(Debug, Clone, Default)]
pub struct AnalysisProgress {
    completed: Vec<String>,
    failed: Vec<(String, String)>,
}

impl AnalysisProgress {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_done(&mut self, pass: impl Into<String>) {
        self.completed.push(pass.into());
    }

    pub fn mark_failed(&mut self, pass: impl Into<String>, reason: impl Into<String>) {
        self.failed.push((pass.into(), reason.into()));
    }

    #[must_use]
    pub fn is_done(&self, pass: &str) -> bool {
        self.completed.iter().any(|p| p == pass)
    }

    #[must_use]
    pub fn has_failed(&self, pass: &str) -> bool {
        self.failed.iter().any(|(p, _)| p == pass)
    }

    #[must_use]
    pub fn all_completed(&self) -> &[String] {
        &self.completed
    }

    #[must_use]
    pub fn all_failed(&self) -> &[(String, String)] {
        &self.failed
    }
}

// ── AnalysisStats ─────────────────────────────────────────────────────────────

/// Summary statistics derived from the context.
#[derive(Debug, Clone, Default)]
pub struct AnalysisStats {
    pub function_count: usize,
    pub string_count: usize,
    pub xref_count: usize,
    pub code_bytes: u64,
    pub data_bytes: u64,
    pub symbolicated_functions: usize,
}

impl fmt::Display for AnalysisStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "functions={} strings={} xrefs={} code={}B data={}B sym={}",
            self.function_count,
            self.string_count,
            self.xref_count,
            self.code_bytes,
            self.data_bytes,
            self.symbolicated_functions,
        )
    }
}

// ── AnalysisCtx ──────────────────────────────────────────────────────────────

/// Central state container for a single binary analysis session.
///
/// All writes are guarded by a frozen flag so that once analysis is complete
/// the context can be sealed and shared via `Arc`.
pub struct AnalysisCtx {
    /// Unique identifier (typically the binary's SHA-256 hash).
    pub id: String,
    /// Human-readable name of the binary.
    pub name: String,
    /// Architecture string.
    pub arch: String,
    /// All discovered functions, keyed by start address.
    functions: HashMap<Addr, FunctionInfo>,
    /// All discovered strings, keyed by address.
    strings: HashMap<Addr, StringInfo>,
    /// Cross-references (from → Vec<XrefInfo>).
    xrefs_from: HashMap<Addr, Vec<XrefInfo>>,
    /// Cross-references (to → Vec<XrefInfo>).
    xrefs_to: HashMap<Addr, Vec<XrefInfo>>,
    /// Analysis pass progress.
    pub progress: AnalysisProgress,
    /// Whether the context is frozen (read-only).
    frozen: bool,
    /// Arbitrary named annotations.
    annotations: HashMap<String, String>,
}

impl AnalysisCtx {
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arch: arch.into(),
            functions: HashMap::new(),
            strings: HashMap::new(),
            xrefs_from: HashMap::new(),
            xrefs_to: HashMap::new(),
            progress: AnalysisProgress::new(),
            frozen: false,
            annotations: HashMap::new(),
        }
    }

    // ── Mutating operations ───────────────────────────────────────────────

    const fn check_frozen(&self) -> CtxResult<()> {
        if self.frozen {
            Err(CtxError::Frozen)
        } else {
            Ok(())
        }
    }

    /// Freeze the context, preventing further modifications.
    pub const fn freeze(&mut self) {
        self.frozen = true;
    }

    #[must_use]
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Insert or update a `FunctionInfo`.
    ///
    /// # Errors
    /// Returns `CtxError::Frozen` if the context is frozen.
    pub fn add_function(&mut self, func: FunctionInfo) -> CtxResult<()> {
        self.check_frozen()?;
        self.functions.insert(func.start, func);
        Ok(())
    }

    /// Insert a `StringInfo`.  Returns an error if one already exists.
    ///
    /// # Errors
    /// Returns `CtxError::Frozen` if frozen or `CtxError::DuplicateString` if a string at that address exists.
    pub fn add_string(&mut self, s: StringInfo) -> CtxResult<()> {
        self.check_frozen()?;
        if self.strings.contains_key(&s.address) {
            return Err(CtxError::DuplicateString(s.address));
        }
        self.strings.insert(s.address, s);
        Ok(())
    }

    /// Insert or silently replace a string.
    ///
    /// # Errors
    /// Returns `CtxError::Frozen` if the context is frozen.
    pub fn upsert_string(&mut self, s: StringInfo) -> CtxResult<()> {
        self.check_frozen()?;
        self.strings.insert(s.address, s);
        Ok(())
    }

    /// Add a cross-reference.
    ///
    /// # Errors
    /// Returns `CtxError::Frozen` if the context is frozen.
    pub fn add_xref(&mut self, xref: XrefInfo) -> CtxResult<()> {
        self.check_frozen()?;
        self.xrefs_from
            .entry(xref.from)
            .or_default()
            .push(xref.clone());
        self.xrefs_to
            .entry(xref.to)
            .or_default()
            .push(xref);
        Ok(())
    }

    /// Add an annotation.
    ///
    /// # Errors
    /// Returns `CtxError::Frozen` if the context is frozen.
    pub fn annotate(&mut self, key: impl Into<String>, value: impl Into<String>) -> CtxResult<()> {
        self.check_frozen()?;
        self.annotations.insert(key.into(), value.into());
        Ok(())
    }

    // ── Query operations ──────────────────────────────────────────────────

    #[must_use]
    pub fn function(&self, addr: Addr) -> Option<&FunctionInfo> {
        self.functions.get(&addr)
    }

    #[must_use]
    pub fn function_mut(&mut self, addr: Addr) -> Option<&mut FunctionInfo> {
        self.functions.get_mut(&addr)
    }

    #[must_use]
    pub const fn functions(&self) -> &HashMap<Addr, FunctionInfo> {
        &self.functions
    }

    #[must_use]
    pub fn string_at(&self, addr: Addr) -> Option<&StringInfo> {
        self.strings.get(&addr)
    }

    #[must_use]
    pub const fn strings(&self) -> &HashMap<Addr, StringInfo> {
        &self.strings
    }

    /// All cross-references originating from `addr`.
    #[must_use]
    pub fn xrefs_from(&self, addr: Addr) -> &[XrefInfo] {
        self.xrefs_from.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// All cross-references targeting `addr`.
    #[must_use]
    pub fn xrefs_to(&self, addr: Addr) -> &[XrefInfo] {
        self.xrefs_to.get(&addr).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str)
    }

    // ── Aggregates ────────────────────────────────────────────────────────

    #[must_use]
    pub fn stats(&self) -> AnalysisStats {
        let symbolicated_functions = self.functions.values().filter(|f| f.has_symbol).count();
        let xref_count = self.xrefs_from.values().map(std::vec::Vec::len).sum();
        let code_bytes = self.functions.values().map(|f| f.length).sum();

        AnalysisStats {
            function_count: self.functions.len(),
            string_count: self.strings.len(),
            xref_count,
            code_bytes,
            data_bytes: 0,
            symbolicated_functions,
        }
    }

    /// Returns all functions whose names match (case-insensitive substring).
    #[must_use]
    pub fn search_functions(&self, query: &str) -> Vec<&FunctionInfo> {
        let q = query.to_lowercase();
        self.functions
            .values()
            .filter(|f| {
                f.name
                    .as_ref()
                    .is_some_and(|n| n.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Returns all strings whose value matches (case-insensitive substring).
    #[must_use]
    pub fn search_strings(&self, query: &str) -> Vec<&StringInfo> {
        let q = query.to_lowercase();
        self.strings
            .values()
            .filter(|s| s.value.to_lowercase().contains(&q))
            .collect()
    }

    /// Returns all call-type xrefs from `addr`.
    #[must_use]
    pub fn callees_of(&self, addr: Addr) -> Vec<Addr> {
        self.xrefs_from(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .map(|x| x.to)
            .collect()
    }

    /// Returns all callers of `addr`.
    #[must_use]
    pub fn callers_of(&self, addr: Addr) -> Vec<Addr> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .map(|x| x.from)
            .collect()
    }

    /// Wraps self in an `Arc` (convenience for sharing with passes).
    #[must_use]
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl fmt::Debug for AnalysisCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalysisCtx")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("arch", &self.arch)
            .field("functions", &self.functions.len())
            .field("strings", &self.strings.len())
            .field("xrefs_from", &self.xrefs_from.len())
            .field("xrefs_to", &self.xrefs_to.len())
            .field("progress", &self.progress)
            .field("frozen", &self.frozen)
            .field("annotations", &self.annotations.len())
            .finish()
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Fluent builder for [`AnalysisCtx`].
#[derive(Default)]
pub struct AnalysisCtxBuilder {
    id: Option<String>,
    name: Option<String>,
    arch: Option<String>,
}

impl AnalysisCtxBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }

    /// # Errors
    /// Returns `CtxError::MissingField` if a required field (`id`) was not set.
    pub fn build(self) -> CtxResult<AnalysisCtx> {
        let id = self.id.ok_or(CtxError::MissingField("id"))?;
        let name = self.name.unwrap_or_else(|| id.clone());
        let arch = self.arch.unwrap_or_else(|| "unknown".to_owned());
        Ok(AnalysisCtx::new(id, name, arch))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> AnalysisCtx {
        AnalysisCtxBuilder::new()
            .id("abc123")
            .name("test.exe")
            .arch("x86_64")
            .build()
            .unwrap()
    }

    #[test]
    fn test_add_function() {
        let mut ctx = make_ctx();
        let mut f = FunctionInfo::new(0x1000);
        f.name = Some("main".to_owned());
        f.length = 100;
        ctx.add_function(f).unwrap();
        assert_eq!(ctx.functions().len(), 1);
        assert_eq!(ctx.function(0x1000).unwrap().display_name(), "main");
    }

    #[test]
    fn test_add_string() {
        let mut ctx = make_ctx();
        let s = StringInfo::new(0x2000, "hello world");
        ctx.add_string(s).unwrap();
        assert_eq!(ctx.strings().len(), 1);
        // Duplicate should fail
        let s2 = StringInfo::new(0x2000, "other");
        assert!(ctx.add_string(s2).is_err());
    }

    #[test]
    fn test_xrefs() {
        let mut ctx = make_ctx();
        ctx.add_xref(XrefInfo::call(0x1000, 0x2000)).unwrap();
        ctx.add_xref(XrefInfo::call(0x1010, 0x2000)).unwrap();
        assert_eq!(ctx.callers_of(0x2000).len(), 2);
        assert_eq!(ctx.callees_of(0x1000).len(), 1);
    }

    #[test]
    fn test_freeze() {
        let mut ctx = make_ctx();
        ctx.freeze();
        let f = FunctionInfo::new(0x1000);
        assert!(ctx.add_function(f).is_err());
    }

    #[test]
    fn test_stats() {
        let mut ctx = make_ctx();
        ctx.add_function(FunctionInfo::new(0x1000)).unwrap();
        ctx.add_xref(XrefInfo::call(0x1000, 0x2000)).unwrap();
        let s = ctx.stats();
        assert_eq!(s.function_count, 1);
        assert_eq!(s.xref_count, 1);
    }

    #[test]
    fn test_search() {
        let mut ctx = make_ctx();
        let mut f = FunctionInfo::new(0x1000);
        f.name = Some("decrypt_payload".to_owned());
        ctx.add_function(f).unwrap();
        assert_eq!(ctx.search_functions("decrypt").len(), 1);
        assert_eq!(ctx.search_functions("encrypt").len(), 0);
    }
}
