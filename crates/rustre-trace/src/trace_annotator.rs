//! Annotate execution traces with symbol names, source locations, and
//! function-level metadata.
//!
//! Provides [`TraceAnnotator`], [`AnnotatedEntry`], and [`SymbolAnnotation`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{TraceEvent, TraceRecord, TraceSession};

// ─── SymbolAnnotation ─────────────────────────────────────────────────────────

/// A symbol resolved at a specific address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolAnnotation {
    /// Virtual address of the symbol.
    pub addr: u64,
    /// Symbol name (demangled if available).
    pub name: String,
    /// Byte offset from the start of the symbol (0 = at the entry point).
    pub offset: u64,
    /// Name of the containing module (DLL/shared library/executable).
    pub module: String,
    /// Source file path, if available.
    pub source_file: Option<String>,
    /// Source line number, if available.
    pub source_line: Option<u32>,
    /// Symbol kind.
    pub kind: SymbolKind,
}

impl SymbolAnnotation {
    /// Return `true` if this annotation has source location information.
    #[must_use]
    pub const fn has_source(&self) -> bool {
        self.source_file.is_some()
    }

    /// Return the fully qualified name including module prefix.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        if self.module.is_empty() {
            self.name.clone()
        } else {
            format!("{}!{}", self.module, self.name)
        }
    }

    /// Return `true` if the address is exactly at the symbol entry point.
    #[must_use]
    pub const fn at_entry(&self) -> bool {
        self.offset == 0
    }
}

impl std::fmt::Display for SymbolAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.offset == 0 {
            write!(f, "{}", self.qualified_name())
        } else {
            write!(f, "{}+{:#x}", self.qualified_name(), self.offset)
        }
    }
}

// ─── SymbolKind ───────────────────────────────────────────────────────────────

/// The kind of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    /// A function (code symbol).
    Function,
    /// A global or static variable (data symbol).
    Data,
    /// A thunk / import stub.
    Thunk,
    /// An unknown / unclassified symbol.
    Unknown,
}

impl std::fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Function => write!(f, "function"),
            Self::Data => write!(f, "data"),
            Self::Thunk => write!(f, "thunk"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─── AnnotationSource ─────────────────────────────────────────────────────────

/// Where a symbol annotation came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnotationSource {
    /// Loaded from a symbol file (PDB, DWARF, etc.).
    SymbolFile(String),
    /// Derived from exported function names in the binary.
    ExportTable,
    /// Synthesised from module base + offset.
    ModuleOffset,
    /// Provided at runtime by a debugger stub.
    DebuggerRuntime,
    /// User-supplied via the annotator API.
    Manual,
}

impl std::fmt::Display for AnnotationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SymbolFile(path) => write!(f, "symfile:{path}"),
            Self::ExportTable => write!(f, "exports"),
            Self::ModuleOffset => write!(f, "module+offset"),
            Self::DebuggerRuntime => write!(f, "debugger"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

// ─── AnnotatedEntry ───────────────────────────────────────────────────────────

/// A single annotated trace record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedEntry {
    /// The underlying trace record.
    pub record: TraceRecord,
    /// Symbol annotation, if resolved.
    pub symbol: Option<SymbolAnnotation>,
    /// Function-level annotation (name of the enclosing function).
    pub function_name: Option<String>,
    /// Module name at this address.
    pub module_name: Option<String>,
    /// Call depth at this point in the trace.
    pub call_depth: u32,
    /// `true` if this record is at a function entry point.
    pub is_function_entry: bool,
    /// `true` if this record is a function return.
    pub is_function_return: bool,
    /// Source of the annotation.
    pub annotation_source: Option<AnnotationSource>,
}

impl AnnotatedEntry {
    /// Create an unannotated entry wrapping `record`.
    #[must_use]
    pub const fn new(record: TraceRecord) -> Self {
        Self {
            record,
            symbol: None,
            function_name: None,
            module_name: None,
            call_depth: 0,
            is_function_entry: false,
            is_function_return: false,
            annotation_source: None,
        }
    }

    /// Return the primary address of the underlying event.
    #[must_use]
    pub const fn addr(&self) -> u64 {
        self.record.event.primary_addr()
    }

    /// Return `true` if any annotation is present.
    #[must_use]
    pub const fn is_annotated(&self) -> bool {
        self.symbol.is_some() || self.function_name.is_some() || self.module_name.is_some()
    }

    /// Render a human-readable summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        let indent = "  ".repeat(self.call_depth as usize);
        let addr = self.addr();
        let sym = self
            .symbol
            .as_ref()
            .map_or_else(|| format!("{addr:#x}"), |s| s.to_string());
        let entry_mark = if self.is_function_entry { " [ENTRY]" } else { "" };
        let ret_mark = if self.is_function_return { " [RET]" } else { "" };
        format!("{indent}{sym}{entry_mark}{ret_mark}")
    }
}

impl std::fmt::Display for AnnotatedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.record.seq, self.summary())
    }
}

// ─── SymbolTable ──────────────────────────────────────────────────────────────

/// A flat symbol table mapping addresses to [`SymbolAnnotation`] records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolTable {
    /// Map from address to annotation.
    symbols: HashMap<u64, SymbolAnnotation>,
    /// Module ranges: `(start, end, name)` for fast module lookup.
    modules: Vec<(u64, u64, String)>,
}

impl SymbolTable {
    /// Create an empty symbol table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol.
    pub fn insert(&mut self, sym: SymbolAnnotation) {
        self.symbols.insert(sym.addr, sym);
    }

    /// Insert a module range.
    pub fn add_module(&mut self, start: u64, end: u64, name: impl Into<String>) {
        self.modules.push((start, end, name.into()));
        self.modules.sort_by_key(|(s, _, _)| *s);
    }

    /// Look up a symbol by exact address.
    #[must_use]
    pub fn get_exact(&self, addr: u64) -> Option<&SymbolAnnotation> {
        self.symbols.get(&addr)
    }

    /// Resolve an address to a symbol, searching backwards for the nearest symbol.
    #[must_use]
    pub fn resolve(&self, addr: u64) -> Option<SymbolAnnotation> {
        // Find the largest symbol address ≤ `addr`.
        let mut best: Option<(&u64, &SymbolAnnotation)> = None;
        for (sym_addr, sym) in &self.symbols {
            if *sym_addr <= addr {
                if best.is_none() || *sym_addr > *best.unwrap().0 {
                    best = Some((sym_addr, sym));
                }
            }
        }

        best.map(|(sym_addr, sym)| SymbolAnnotation {
            addr: *sym_addr,
            name: sym.name.clone(),
            offset: addr - *sym_addr,
            module: sym.module.clone(),
            source_file: sym.source_file.clone(),
            source_line: sym.source_line,
            kind: sym.kind,
        })
    }

    /// Look up the module name for an address.
    #[must_use]
    pub fn module_for_addr(&self, addr: u64) -> Option<&str> {
        for (start, end, name) in &self.modules {
            if addr >= *start && addr < *end {
                return Some(name.as_str());
            }
        }
        None
    }

    /// Number of symbols in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns `true` if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Return all symbols sorted by address.
    #[must_use]
    pub fn sorted_symbols(&self) -> Vec<&SymbolAnnotation> {
        let mut syms: Vec<&SymbolAnnotation> = self.symbols.values().collect();
        syms.sort_by_key(|s| s.addr);
        syms
    }

    /// Build a symbol table from a flat list of (addr, name, module) triples.
    #[must_use]
    pub fn from_flat(entries: &[(u64, &str, &str)]) -> Self {
        let mut table = Self::new();
        for &(addr, name, module) in entries {
            table.insert(SymbolAnnotation {
                addr,
                name: name.to_string(),
                offset: 0,
                module: module.to_string(),
                source_file: None,
                source_line: None,
                kind: SymbolKind::Function,
            });
        }
        table
    }
}

// ─── AnnotatorConfig ──────────────────────────────────────────────────────────

/// Configuration for the [`TraceAnnotator`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatorConfig {
    /// Whether to track and annotate call depth.
    pub track_call_depth: bool,
    /// Whether to mark function entry points.
    pub mark_function_entries: bool,
    /// Whether to mark function returns.
    pub mark_function_returns: bool,
    /// Whether to annotate module names.
    pub annotate_modules: bool,
    /// Annotation source label to attach.
    pub source_label: AnnotationSource,
}

impl Default for AnnotatorConfig {
    fn default() -> Self {
        Self {
            track_call_depth: true,
            mark_function_entries: true,
            mark_function_returns: true,
            annotate_modules: true,
            source_label: AnnotationSource::Manual,
        }
    }
}

// ─── AnnotationStats ──────────────────────────────────────────────────────────

/// Statistics from an annotation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnnotationStats {
    /// Total entries annotated.
    pub total_entries: usize,
    /// Entries with a resolved symbol.
    pub resolved_symbols: usize,
    /// Entries with module information.
    pub with_module: usize,
    /// Entries at function entry points.
    pub function_entries: usize,
    /// Entries at function returns.
    pub function_returns: usize,
    /// Maximum call depth observed.
    pub max_call_depth: u32,
}

impl AnnotationStats {
    /// Symbol resolution rate as a percentage.
    #[must_use]
    pub fn resolution_rate(&self) -> f64 {
        if self.total_entries == 0 {
            return 0.0;
        }
        (self.resolved_symbols as f64 / self.total_entries as f64) * 100.0
    }
}

impl std::fmt::Display for AnnotationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "entries={} resolved={} ({:.1}%) entries={} returns={} max_depth={}",
            self.total_entries,
            self.resolved_symbols,
            self.resolution_rate(),
            self.function_entries,
            self.function_returns,
            self.max_call_depth
        )
    }
}

// ─── TraceAnnotator ───────────────────────────────────────────────────────────

/// Annotates trace records with symbol names and function-level metadata.
///
/// # Example
/// ```
/// # use rustre_trace::trace_annotator::{TraceAnnotator, SymbolTable};
/// # use rustre_trace::TraceSession;
/// let table = SymbolTable::from_flat(&[(0x1000, "main", "app")]);
/// let annotator = TraceAnnotator::new(table);
/// let session = TraceSession::new("test", "x86_64");
/// let (entries, stats) = annotator.annotate(&session);
/// println!("{}", stats);
/// ```
pub struct TraceAnnotator {
    /// Symbol table used for resolution.
    pub symbol_table: SymbolTable,
    /// Configuration.
    pub config: AnnotatorConfig,
}

impl TraceAnnotator {
    /// Create a new annotator with the given symbol table and default config.
    #[must_use]
    pub fn new(symbol_table: SymbolTable) -> Self {
        Self {
            symbol_table,
            config: AnnotatorConfig::default(),
        }
    }

    /// Create an annotator with explicit config.
    #[must_use]
    pub const fn with_config(symbol_table: SymbolTable, config: AnnotatorConfig) -> Self {
        Self { symbol_table, config }
    }

    /// Annotate all records in `session` and return annotated entries + stats.
    #[must_use]
    pub fn annotate(&self, session: &TraceSession) -> (Vec<AnnotatedEntry>, AnnotationStats) {
        let mut entries = Vec::with_capacity(session.records.len());
        let mut stats = AnnotationStats {
            total_entries: session.records.len(),
            ..Default::default()
        };
        let mut call_depth: u32 = 0;

        for rec in &session.records {
            let mut entry = AnnotatedEntry::new(rec.clone());

            // Resolve symbol.
            let addr = rec.event.primary_addr();
            if let Some(sym) = self.symbol_table.resolve(addr) {
                entry.function_name = Some(sym.name.clone());
                entry.symbol = Some(sym);
                entry.annotation_source = Some(self.config.source_label.clone());
                stats.resolved_symbols += 1;
            }

            // Module annotation.
            if self.config.annotate_modules {
                if let Some(module) = self.symbol_table.module_for_addr(addr) {
                    entry.module_name = Some(module.to_string());
                    stats.with_module += 1;
                }
            }

            // Call/return tracking.
            if self.config.track_call_depth {
                match &rec.event {
                    TraceEvent::Call { .. } => {
                        call_depth = call_depth.saturating_add(1);
                        if self.config.mark_function_entries {
                            entry.is_function_entry = true;
                            stats.function_entries += 1;
                        }
                    }
                    TraceEvent::Return { .. } => {
                        if self.config.mark_function_returns {
                            entry.is_function_return = true;
                            stats.function_returns += 1;
                        }
                        call_depth = call_depth.saturating_sub(1);
                    }
                    TraceEvent::Instruction { addr, .. } => {
                        // Mark instruction events at known function entry points.
                        if self.config.mark_function_entries
                            && self.symbol_table.get_exact(*addr).is_some()
                        {
                            entry.is_function_entry = true;
                            stats.function_entries += 1;
                        }
                    }
                    _ => {}
                }
            }

            entry.call_depth = call_depth;
            stats.max_call_depth = stats.max_call_depth.max(call_depth);
            entries.push(entry);
        }

        (entries, stats)
    }

    /// Annotate a single record.
    #[must_use]
    pub fn annotate_record(&self, rec: &TraceRecord, call_depth: u32) -> AnnotatedEntry {
        let mut entry = AnnotatedEntry::new(rec.clone());
        let addr = rec.event.primary_addr();

        if let Some(sym) = self.symbol_table.resolve(addr) {
            entry.function_name = Some(sym.name.clone());
            entry.symbol = Some(sym);
            entry.annotation_source = Some(self.config.source_label.clone());
        }

        if self.config.annotate_modules {
            if let Some(module) = self.symbol_table.module_for_addr(addr) {
                entry.module_name = Some(module.to_string());
            }
        }

        if self.symbol_table.get_exact(addr).is_some() && self.config.mark_function_entries {
            entry.is_function_entry = true;
        }

        entry.call_depth = call_depth;
        entry
    }

    /// Filter annotated entries to only those with resolved symbols.
    #[must_use]
    pub fn filter_resolved(entries: &[AnnotatedEntry]) -> Vec<&AnnotatedEntry> {
        entries.iter().filter(|e| e.symbol.is_some()).collect()
    }

    /// Group annotated entries by function name.
    #[must_use]
    pub fn group_by_function(entries: &[AnnotatedEntry]) -> HashMap<String, Vec<usize>> {
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            if let Some(name) = &entry.function_name {
                map.entry(name.clone()).or_default().push(idx);
            }
        }
        map
    }

    /// Count the number of entries per module.
    #[must_use]
    pub fn module_hit_counts(entries: &[AnnotatedEntry]) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for entry in entries {
            if let Some(module) = &entry.module_name {
                *map.entry(module.clone()).or_insert(0) += 1;
            }
        }
        map
    }

    /// Build a call graph adjacency list from annotated entries.
    ///
    /// Returns `HashMap<caller_name, Vec<callee_name>>`.
    #[must_use]
    pub fn build_call_graph(entries: &[AnnotatedEntry]) -> HashMap<String, Vec<String>> {
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        let mut call_stack: Vec<String> = Vec::new();

        for entry in entries {
            if entry.is_function_entry {
                if let Some(name) = &entry.function_name {
                    if let Some(caller) = call_stack.last() {
                        graph
                            .entry(caller.clone())
                            .or_default()
                            .push(name.clone());
                    }
                    call_stack.push(name.clone());
                }
            }
            if entry.is_function_return {
                call_stack.pop();
            }
        }

        graph
    }

    /// Summarize the top N functions by execution count.
    #[must_use]
    pub fn top_functions(entries: &[AnnotatedEntry], n: usize) -> Vec<(String, usize)> {
        let groups = Self::group_by_function(entries);
        let mut pairs: Vec<(String, usize)> = groups
            .into_iter()
            .map(|(k, v)| (k, v.len()))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Reconstruct an annotated [`TraceSession`] from entries.
    #[must_use]
    pub fn entries_to_session(entries: &[AnnotatedEntry]) -> TraceSession {
        let mut session = TraceSession::new("annotated", "unknown");
        for entry in entries {
            session.push(
                entry.record.event.clone(),
                entry.record.thread_id,
                entry.record.timestamp_ns,
            );
        }
        session
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceEvent, TraceSession};

    fn make_symbol_table() -> SymbolTable {
        SymbolTable::from_flat(&[
            (0x1000, "main", "app"),
            (0x1100, "helper", "app"),
            (0x2000, "malloc", "libc"),
        ])
    }

    fn make_session_with_calls() -> TraceSession {
        let mut s = TraceSession::new("test", "x86_64");
        s.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, 0);
        s.push(TraceEvent::Call { from: 0x1010, to: 0x1100 }, 1, 100);
        s.push(TraceEvent::Instruction { addr: 0x1100, size: 3 }, 1, 200);
        s.push(TraceEvent::Return { from: 0x1150, to: 0x1014 }, 1, 300);
        s.push(TraceEvent::Instruction { addr: 0x1014, size: 5 }, 1, 400);
        s
    }

    #[test]
    fn test_annotate_resolves_symbols() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let session = make_session_with_calls();
        let (entries, stats) = annotator.annotate(&session);
        assert_eq!(entries.len(), 5);
        assert!(stats.resolved_symbols > 0);
    }

    #[test]
    fn test_symbol_at_entry_point() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let session = make_session_with_calls();
        let (entries, _) = annotator.annotate(&session);
        // First entry is at 0x1000 = main
        assert!(entries[0].is_function_entry);
    }

    #[test]
    fn test_call_depth_tracking() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let session = make_session_with_calls();
        let (entries, stats) = annotator.annotate(&session);
        // After Call event, depth should be 1
        assert_eq!(entries[2].call_depth, 1);
        assert!(stats.max_call_depth >= 1);
    }

    #[test]
    fn test_function_return_marked() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let session = make_session_with_calls();
        let (entries, stats) = annotator.annotate(&session);
        // Return event at index 3
        assert!(entries[3].is_function_return);
        assert_eq!(stats.function_returns, 1);
    }

    #[test]
    fn test_symbol_offset() {
        let table = make_symbol_table();
        // An address inside `main` (0x1000 + 4)
        let sym = table.resolve(0x1004).unwrap();
        assert_eq!(sym.name, "main");
        assert_eq!(sym.offset, 4);
    }

    #[test]
    fn test_symbol_at_exact() {
        let table = make_symbol_table();
        let sym = table.resolve(0x1000).unwrap();
        assert_eq!(sym.name, "main");
        assert!(sym.at_entry());
    }

    #[test]
    fn test_module_lookup() {
        let mut table = SymbolTable::new();
        table.add_module(0x1000, 0x2000, "app");
        table.add_module(0x2000, 0x3000, "libc");
        assert_eq!(table.module_for_addr(0x1500), Some("app"));
        assert_eq!(table.module_for_addr(0x2500), Some("libc"));
        assert_eq!(table.module_for_addr(0x5000), None);
    }

    #[test]
    fn test_filter_resolved() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let session = make_session_with_calls();
        let (entries, _) = annotator.annotate(&session);
        let resolved = TraceAnnotator::filter_resolved(&entries);
        assert!(!resolved.is_empty());
        for e in resolved {
            assert!(e.symbol.is_some());
        }
    }

    #[test]
    fn test_group_by_function() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let session = make_session_with_calls();
        let (entries, _) = annotator.annotate(&session);
        let groups = TraceAnnotator::group_by_function(&entries);
        assert!(groups.contains_key("main") || groups.contains_key("helper"));
    }

    #[test]
    fn test_top_functions() {
        let table = make_symbol_table();
        let annotator = TraceAnnotator::new(table);
        let mut session = TraceSession::new("test", "x86_64");
        for _ in 0..10 {
            session.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, 0);
        }
        for _ in 0..3 {
            session.push(TraceEvent::Instruction { addr: 0x1100, size: 4 }, 1, 0);
        }
        let (entries, _) = annotator.annotate(&session);
        let top = TraceAnnotator::top_functions(&entries, 2);
        assert!(!top.is_empty());
        // main should be at the top
        assert_eq!(top[0].0, "main");
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_qualified_name() {
        let sym = SymbolAnnotation {
            addr: 0x1000,
            name: "main".to_string(),
            offset: 0,
            module: "app".to_string(),
            source_file: None,
            source_line: None,
            kind: SymbolKind::Function,
        };
        assert_eq!(sym.qualified_name(), "app!main");
    }

    #[test]
    fn test_empty_module_qualified_name() {
        let sym = SymbolAnnotation {
            addr: 0x1000,
            name: "sub_1000".to_string(),
            offset: 0,
            module: String::new(),
            source_file: None,
            source_line: None,
            kind: SymbolKind::Function,
        };
        assert_eq!(sym.qualified_name(), "sub_1000");
    }

    #[test]
    fn test_symbol_table_len() {
        let table = make_symbol_table();
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_annotation_stats_display() {
        let stats = AnnotationStats {
            total_entries: 100,
            resolved_symbols: 80,
            with_module: 90,
            function_entries: 10,
            function_returns: 10,
            max_call_depth: 5,
        };
        let s = stats.to_string();
        assert!(s.contains("80.0"));
    }
}
