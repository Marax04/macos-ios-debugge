// trace_annotation.rs — Annotate execution traces with semantic information
//
// Attaches symbol names, function boundaries, YARA match hits, data type
// annotations, source-level mappings, and taint labels to raw trace records.
// Multiple annotation sources can be merged with configurable priority.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use serde::{Deserialize, Serialize};

use super::trace_format::TraceRecord;

// ── Source of an annotation ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnnotationSource {
    /// Imported from a symbol file (PDB, DWARF, ELF symbols).
    SymbolFile(String),
    /// Derived from a YARA scan.
    Yara,
    /// Derived from a disassembler or lifter.
    Disassembler,
    /// Source-level debug info (DWARF line info, PDB source map).
    DebugInfo,
    /// User-added comment.
    User,
    /// Derived from taint propagation.
    Taint,
    /// Derived from type inference.
    TypeInference,
    /// Derived from a MISP/threat-intel correlation.
    ThreatIntel,
    /// Derived from a heuristic.
    Heuristic(String),
}

impl fmt::Display for AnnotationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnotationSource::SymbolFile(s) => write!(f, "sym:{s}"),
            AnnotationSource::Yara => write!(f, "yara"),
            AnnotationSource::Disassembler => write!(f, "disasm"),
            AnnotationSource::DebugInfo => write!(f, "debug"),
            AnnotationSource::User => write!(f, "user"),
            AnnotationSource::Taint => write!(f, "taint"),
            AnnotationSource::TypeInference => write!(f, "type"),
            AnnotationSource::ThreatIntel => write!(f, "ti"),
            AnnotationSource::Heuristic(h) => write!(f, "heur:{h}"),
        }
    }
}

// ── Annotation kinds ─────────────────────────────────────────────────────────

/// Classification of what an annotation conveys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnnotationKind {
    /// A symbolic name for an address (function, label, import).
    Symbol { name: String, demangled: Option<String> },
    /// Function start/end boundary.
    FunctionBoundary { start: u64, end: u64, name: String },
    /// A YARA rule hit at this address range.
    YaraHit { rule: String, namespace: Option<String>, tags: Vec<String> },
    /// Data type annotation (e.g. "`UNICODE_STRING`*").
    DataType { type_name: String, size_bytes: Option<u32> },
    /// Source file / line information.
    SourceLocation { file: String, line: u32, column: Option<u32> },
    /// Taint label propagated to this PC / memory address.
    TaintLabel { label: String, source_addr: u64 },
    /// Threat intelligence tag (MISP attribute type + value).
    ThreatTag { ioc_type: String, ioc_value: String, event_id: Option<String> },
    /// Arbitrary user comment.
    Comment(String),
    /// API or library call target name.
    LibraryCall { library: String, function: String },
    /// Loop head annotation.
    LoopHead { estimated_iterations: Option<u64> },
    /// Instruction category label (e.g. "crypto", "compression").
    Category(String),
}

impl fmt::Display for AnnotationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnotationKind::Symbol { name, .. } => write!(f, "sym:{name}"),
            AnnotationKind::FunctionBoundary { name, .. } => write!(f, "fn:{name}"),
            AnnotationKind::YaraHit { rule, .. } => write!(f, "yara:{rule}"),
            AnnotationKind::DataType { type_name, .. } => write!(f, "type:{type_name}"),
            AnnotationKind::SourceLocation { file, line, .. } => write!(f, "src:{file}:{line}"),
            AnnotationKind::TaintLabel { label, .. } => write!(f, "taint:{label}"),
            AnnotationKind::ThreatTag { ioc_type, ioc_value, .. } => write!(f, "ti:{ioc_type}:{ioc_value}"),
            AnnotationKind::Comment(s) => write!(f, "comment:{s}"),
            AnnotationKind::LibraryCall { library, function } => write!(f, "call:{library}.{function}"),
            AnnotationKind::LoopHead { .. } => write!(f, "loop"),
            AnnotationKind::Category(c) => write!(f, "cat:{c}"),
        }
    }
}

// ── A single annotation ───────────────────────────────────────────────────────

/// A single annotation attached to a PC address (or address range).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAnnotation {
    /// The PC address this annotation applies to.
    pub pc: u64,
    /// Optional end address for range annotations.
    pub pc_end: Option<u64>,
    /// Sequence number from the trace (record index).
    pub record_index: Option<u64>,
    /// Thread ID, if relevant.
    pub tid: Option<u32>,
    /// The annotation content.
    pub kind: AnnotationKind,
    /// Where this annotation came from.
    pub source: AnnotationSource,
    /// Confidence 0.0–1.0.
    pub confidence: f32,
}

impl TraceAnnotation {
    #[must_use]
    pub const fn new(pc: u64, kind: AnnotationKind, source: AnnotationSource) -> Self {
        TraceAnnotation {
            pc,
            pc_end: None,
            record_index: None,
            tid: None,
            kind,
            source,
            confidence: 1.0,
        }
    }

    #[must_use]
    pub const fn with_confidence(mut self, c: f32) -> Self {
        // `clamp` propagates NaN rather than sanitising it; a NaN confidence
        // loses every comparison it takes part in, so the annotation would drop
        // out of every ranking and threshold silently.
        self.confidence = if c.is_nan() { 0.0 } else { c.clamp(0.0, 1.0) };
        self
    }

    #[must_use]
    pub const fn with_range(mut self, end: u64) -> Self {
        self.pc_end = Some(end);
        self
    }

    #[must_use]
    pub const fn with_record_index(mut self, idx: u64) -> Self {
        self.record_index = Some(idx);
        self
    }

    #[must_use]
    pub const fn with_tid(mut self, tid: u32) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Returns true if this annotation covers `addr` (point or range).
    #[must_use]
    pub const fn covers(&self, addr: u64) -> bool {
        match self.pc_end {
            Some(end) => addr >= self.pc && addr < end,
            None => addr == self.pc,
        }
    }
}

// ── Symbol table ─────────────────────────────────────────────────────────────

/// A flat symbol → address table used to resolve addresses during annotation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SymbolTable {
    /// address → (name, demangled)
    pub by_addr: BTreeMap<u64, (String, Option<String>)>,
    /// name → address
    pub by_name: HashMap<String, u64>,
}

impl SymbolTable {
    #[must_use]
    pub fn new() -> Self { SymbolTable::default() }

    pub fn insert(&mut self, addr: u64, name: impl Into<String>, demangled: Option<String>) {
        let n = name.into();
        self.by_name.insert(n.clone(), addr);
        self.by_addr.insert(addr, (n, demangled));
    }

    #[must_use]
    pub fn lookup_addr(&self, addr: u64) -> Option<(&str, Option<&str>)> {
        self.by_addr.get(&addr).map(|(n, d)| (n.as_str(), d.as_deref()))
    }

    /// Find the nearest symbol at or before `addr`.
    #[must_use]
    pub fn nearest_before(&self, addr: u64) -> Option<(u64, &str)> {
        self.by_addr.range(..=addr).next_back().map(|(&a, (n, _))| (a, n.as_str()))
    }

    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }
}

// ── Function map ─────────────────────────────────────────────────────────────

/// Describes the boundary of a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBoundary {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub module: Option<String>,
}

impl FunctionBoundary {
    pub fn new(start: u64, end: u64, name: impl Into<String>) -> Self {
        FunctionBoundary { start, end, name: name.into(), module: None }
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// Collection of function boundaries, searchable by address.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FunctionMap {
    /// Sorted by start address.
    functions: Vec<FunctionBoundary>,
}

impl FunctionMap {
    #[must_use]
    pub fn new() -> Self { FunctionMap::default() }

    pub fn insert(&mut self, fb: FunctionBoundary) {
        let idx = self.functions.partition_point(|f| f.start < fb.start);
        self.functions.insert(idx, fb);
    }

    #[must_use]
    pub fn find(&self, addr: u64) -> Option<&FunctionBoundary> {
        let idx = self.functions.partition_point(|f| f.start <= addr);
        if idx == 0 { return None; }
        let fb = &self.functions[idx - 1];
        if fb.contains(addr) { Some(fb) } else { None }
    }

    #[must_use]
    pub const fn len(&self) -> usize { self.functions.len() }
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.functions.is_empty() }
}

// ── YARA hit record ───────────────────────────────────────────────────────────

/// A YARA rule match at a specific address range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraHitRecord {
    pub rule: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub start_addr: u64,
    pub end_addr: u64,
    pub matched_bytes: Vec<u8>,
}

impl YaraHitRecord {
    pub fn new(rule: impl Into<String>, start: u64, end: u64) -> Self {
        YaraHitRecord {
            rule: rule.into(),
            namespace: None,
            tags: Vec::new(),
            start_addr: start,
            end_addr: end,
            matched_bytes: Vec::new(),
        }
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }
}

// ── Annotated trace ───────────────────────────────────────────────────────────

/// A trace enhanced with semantic annotations.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnnotatedTrace {
    /// Annotations indexed by PC.
    by_pc: BTreeMap<u64, Vec<TraceAnnotation>>,
    /// Annotations indexed by record sequence number.
    by_record: BTreeMap<u64, Vec<usize>>,
    /// All annotations in insertion order.
    annotations: Vec<TraceAnnotation>,
    /// PC addresses that have been visited by any record.
    pub seen_pcs: HashSet<u64>,
    /// Total original trace records processed.
    pub record_count: u64,
}

impl AnnotatedTrace {
    #[must_use]
    pub fn new() -> Self { AnnotatedTrace::default() }

    pub fn add(&mut self, ann: TraceAnnotation) {
        let global_idx = self.annotations.len();
        let pc = ann.pc;

        if let Some(rec) = ann.record_index {
            self.by_record.entry(rec).or_default().push(global_idx);
        }

        self.by_pc.entry(pc).or_default().push(ann.clone());
        self.annotations.push(ann);
    }

    /// All annotations at exactly `pc`.
    #[must_use]
    pub fn at_pc(&self, pc: u64) -> &[TraceAnnotation] {
        self.by_pc.get(&pc).map(std::vec::Vec::as_slice).unwrap_or(&[])
    }

    /// All annotations that cover `addr` (including range annotations).
    #[must_use]
    pub fn covering(&self, addr: u64) -> Vec<&TraceAnnotation> {
        self.annotations.iter().filter(|a| a.covers(addr)).collect()
    }

    /// Annotations for a specific record index.
    #[must_use]
    pub fn for_record(&self, idx: u64) -> Vec<&TraceAnnotation> {
        match self.by_record.get(&idx) {
            Some(indices) => indices.iter().map(|&i| &self.annotations[i]).collect(),
            None => Vec::new(),
        }
    }

    /// All annotations from a specific source.
    #[must_use]
    pub fn from_source(&self, source: &AnnotationSource) -> Vec<&TraceAnnotation> {
        self.annotations.iter().filter(|a| &a.source == source).collect()
    }

    /// All symbol annotations.
    #[must_use]
    pub fn symbols(&self) -> Vec<&TraceAnnotation> {
        self.annotations.iter().filter(|a| matches!(&a.kind, AnnotationKind::Symbol { .. })).collect()
    }

    /// All YARA hit annotations.
    #[must_use]
    pub fn yara_hits(&self) -> Vec<&TraceAnnotation> {
        self.annotations.iter().filter(|a| matches!(&a.kind, AnnotationKind::YaraHit { .. })).collect()
    }

    #[must_use]
    pub const fn annotation_count(&self) -> usize { self.annotations.len() }
    #[must_use]
    pub fn annotated_pc_count(&self) -> usize { self.by_pc.len() }
}

// ── Annotation engine ─────────────────────────────────────────────────────────

/// Configuration for the trace annotator.
#[derive(Debug, Clone)]
pub struct AnnotatorConfig {
    /// Whether to emit symbol annotations for every known PC in the trace.
    pub annotate_symbols: bool,
    /// Whether to emit function boundary annotations.
    pub annotate_functions: bool,
    /// Whether to apply YARA hit annotations.
    pub annotate_yara: bool,
    /// Whether to emit loop head annotations based on back-edge heuristic.
    pub annotate_loops: bool,
    /// Whether to emit library call annotations for IAT-resolution.
    pub annotate_lib_calls: bool,
    /// Minimum confidence to include an annotation.
    pub min_confidence: f32,
    /// Maximum annotations per PC (0 = unlimited).
    pub max_per_pc: usize,
}

impl Default for AnnotatorConfig {
    fn default() -> Self {
        AnnotatorConfig {
            annotate_symbols: true,
            annotate_functions: true,
            annotate_yara: true,
            annotate_loops: true,
            annotate_lib_calls: true,
            min_confidence: 0.0,
            max_per_pc: 0,
        }
    }
}

/// Main annotation engine — processes trace records and produces an `AnnotatedTrace`.
pub struct TraceAnnotator {
    config: AnnotatorConfig,
    symbols: SymbolTable,
    functions: FunctionMap,
    yara_hits: Vec<YaraHitRecord>,
    /// (pc, library, `function_name`)
    iat_entries: Vec<(u64, String, String)>,
    /// Back edges: (from, to)
    known_back_edges: Vec<(u64, u64)>,
    /// Custom annotations to inject regardless of trace content.
    user_annotations: Vec<TraceAnnotation>,
}

impl TraceAnnotator {
    #[must_use]
    pub fn new() -> Self {
        TraceAnnotator {
            config: AnnotatorConfig::default(),
            symbols: SymbolTable::new(),
            functions: FunctionMap::new(),
            yara_hits: Vec::new(),
            iat_entries: Vec::new(),
            known_back_edges: Vec::new(),
            user_annotations: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_config(mut self, config: AnnotatorConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_symbol(&mut self, addr: u64, name: impl Into<String>, demangled: Option<String>) {
        self.symbols.insert(addr, name, demangled);
    }

    pub fn add_function(&mut self, fb: FunctionBoundary) {
        self.functions.insert(fb);
    }

    pub fn add_yara_hit(&mut self, hit: YaraHitRecord) {
        self.yara_hits.push(hit);
    }

    pub fn add_iat_entry(&mut self, pc: u64, library: impl Into<String>, function: impl Into<String>) {
        self.iat_entries.push((pc, library.into(), function.into()));
    }

    pub fn add_back_edge(&mut self, from: u64, to: u64) {
        self.known_back_edges.push((from, to));
    }

    pub fn add_user_annotation(&mut self, ann: TraceAnnotation) {
        self.user_annotations.push(ann);
    }

    /// Process trace records and produce an `AnnotatedTrace`.
    #[must_use]
    pub fn annotate(&self, records: &[TraceRecord]) -> AnnotatedTrace {
        let mut at = AnnotatedTrace::new();
        at.record_count = records.len() as u64;

        // Track which PCs we've already annotated for symbol/function, to avoid duplicates.
        let mut sym_annotated: HashSet<u64> = HashSet::new();
        let mut fn_annotated: HashSet<u64> = HashSet::new();

        for (idx, rec) in records.iter().enumerate() {
            at.seen_pcs.insert(rec.pc);

            // Symbol annotation.
            if self.config.annotate_symbols && !sym_annotated.contains(&rec.pc) {
                if let Some((name, demangled)) = self.symbols.lookup_addr(rec.pc) {
                    let ann = TraceAnnotation::new(
                        rec.pc,
                        AnnotationKind::Symbol {
                            name: name.to_string(),
                            demangled: demangled.map(std::string::ToString::to_string),
                        },
                        AnnotationSource::SymbolFile("symbols".into()),
                    )
                    .with_record_index(idx as u64)
                    .with_tid(rec.tid);

                    if ann.confidence >= self.config.min_confidence {
                        at.add(ann);
                        sym_annotated.insert(rec.pc);
                    }
                }
            }

            // Function boundary annotation.
            if self.config.annotate_functions && !fn_annotated.contains(&rec.pc) {
                if let Some(fb) = self.functions.find(rec.pc) {
                    // Only annotate at function entry.
                    if rec.pc == fb.start {
                        let ann = TraceAnnotation::new(
                            fb.start,
                            AnnotationKind::FunctionBoundary {
                                start: fb.start,
                                end: fb.end,
                                name: fb.name.clone(),
                            },
                            AnnotationSource::Disassembler,
                        )
                        .with_range(fb.end)
                        .with_record_index(idx as u64)
                        .with_tid(rec.tid);

                        at.add(ann);
                        fn_annotated.insert(fb.start);
                    }
                }
            }

            // YARA hit annotation.
            if self.config.annotate_yara {
                for hit in &self.yara_hits {
                    if hit.contains(rec.pc) {
                        let already = at.at_pc(rec.pc).iter().any(|a| {
                            matches!(&a.kind, AnnotationKind::YaraHit { rule, .. } if rule == &hit.rule)
                        });
                        if !already {
                            let ann = TraceAnnotation::new(
                                rec.pc,
                                AnnotationKind::YaraHit {
                                    rule: hit.rule.clone(),
                                    namespace: hit.namespace.clone(),
                                    tags: hit.tags.clone(),
                                },
                                AnnotationSource::Yara,
                            )
                            .with_range(hit.end_addr)
                            .with_record_index(idx as u64)
                            .with_tid(rec.tid);
                            at.add(ann);
                        }
                    }
                }
            }

            // Library call annotation.
            if self.config.annotate_lib_calls {
                for (iat_pc, lib, func) in &self.iat_entries {
                    if rec.pc == *iat_pc {
                        let ann = TraceAnnotation::new(
                            rec.pc,
                            AnnotationKind::LibraryCall {
                                library: lib.clone(),
                                function: func.clone(),
                            },
                            AnnotationSource::SymbolFile("iat".into()),
                        )
                        .with_record_index(idx as u64)
                        .with_tid(rec.tid);
                        at.add(ann);
                    }
                }
            }
        }

        // Loop head annotations (from known back edges).
        if self.config.annotate_loops {
            for &(_from, to) in &self.known_back_edges {
                if at.seen_pcs.contains(&to) {
                    let already = at.at_pc(to).iter().any(|a| matches!(a.kind, AnnotationKind::LoopHead { .. }));
                    if !already {
                        let ann = TraceAnnotation::new(
                            to,
                            AnnotationKind::LoopHead { estimated_iterations: None },
                            AnnotationSource::Heuristic("back_edge".into()),
                        )
                        .with_confidence(0.8);
                        if ann.confidence >= self.config.min_confidence {
                            at.add(ann);
                        }
                    }
                }
            }
        }

        // Inject user annotations.
        for ann in &self.user_annotations {
            at.add(ann.clone());
        }

        // Apply max_per_pc limit (trim excess from each PC bucket).
        if self.config.max_per_pc > 0 {
            for (_, anns) in at.by_pc.iter_mut() {
                anns.truncate(self.config.max_per_pc);
            }
        }

        at
    }
}

impl Default for TraceAnnotator {
    fn default() -> Self { TraceAnnotator::new() }
}

// ── Multi-source merger ───────────────────────────────────────────────────────

/// Merges annotation sets from multiple sources with configurable priority.
pub struct AnnotationMerger {
    /// Ordered list of (source, annotations) pairs; lower index = higher priority.
    sources: Vec<(String, Vec<TraceAnnotation>)>,
    /// Whether to deduplicate annotations with the same (pc, kind discriminant).
    deduplicate: bool,
}

impl AnnotationMerger {
    #[must_use]
    pub const fn new() -> Self {
        AnnotationMerger { sources: Vec::new(), deduplicate: true }
    }

    #[must_use]
    pub const fn without_deduplication(mut self) -> Self {
        self.deduplicate = false;
        self
    }

    pub fn add_source(&mut self, name: impl Into<String>, annotations: Vec<TraceAnnotation>) {
        self.sources.push((name.into(), annotations));
    }

    /// Merge all sources into a single `AnnotatedTrace`.
    #[must_use]
    pub fn merge(self) -> AnnotatedTrace {
        let mut result = AnnotatedTrace::new();
        // Key = (pc, kind_tag) for deduplication.
        let mut seen: HashSet<(u64, String)> = HashSet::new();

        for (_, annotations) in self.sources {
            for ann in annotations {
                if self.deduplicate {
                    let key = (ann.pc, format!("{}", ann.kind));
                    if !seen.insert(key) {
                        continue;
                    }
                }
                result.add(ann);
            }
        }

        result
    }
}

impl Default for AnnotationMerger {
    fn default() -> Self { AnnotationMerger::new() }
}

// ── Annotation serialization helpers ─────────────────────────────────────────

/// Serialize an `AnnotatedTrace` summary to a human-readable report string.
#[must_use]
pub fn render_annotation_report(at: &AnnotatedTrace) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "=== Trace Annotation Report ===\n\
         Total annotations   : {}\n\
         Annotated PCs       : {}\n\
         Seen PCs            : {}\n\
         Total records       : {}\n\n",
        at.annotation_count(),
        at.annotated_pc_count(),
        at.seen_pcs.len(),
        at.record_count,
    ));

    let syms = at.symbols();
    out.push_str(&format!("Symbols ({}):\n", syms.len()));
    for ann in syms.iter().take(20) {
        if let AnnotationKind::Symbol { name, .. } = &ann.kind {
            out.push_str(&format!("  0x{:016x}  {}\n", ann.pc, name));
        }
    }
    if syms.len() > 20 {
        out.push_str(&format!("  ... and {} more\n", syms.len() - 20));
    }

    let yara = at.yara_hits();
    if !yara.is_empty() {
        out.push_str(&format!("\nYARA Hits ({}):\n", yara.len()));
        for ann in yara.iter().take(10) {
            if let AnnotationKind::YaraHit { rule, .. } = &ann.kind {
                out.push_str(&format!("  0x{:016x}  {}\n", ann.pc, rule));
            }
        }
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_format::TraceRecord;

    fn make_insn(idx: u64, tid: u32, pc: u64) -> TraceRecord {
        TraceRecord::new_insn(idx, tid, pc)
    }

    fn make_bb(idx: u64, tid: u32, pc: u64) -> TraceRecord {
        TraceRecord::new_bb(idx, tid, pc, 16)
    }

    fn make_call(idx: u64, tid: u32, pc: u64, target: u64) -> TraceRecord {
        TraceRecord::new_call(idx, tid, pc, target)
    }

    fn build_annotator() -> TraceAnnotator {
        let mut ann = TraceAnnotator::new();
        ann.add_symbol(0x1000, "main", Some("main()".into()));
        ann.add_symbol(0x2000, "malloc", None);
        ann.add_function(FunctionBoundary::new(0x1000, 0x1100, "main"));
        ann.add_function(FunctionBoundary::new(0x2000, 0x2050, "malloc"));
        ann.add_yara_hit(YaraHitRecord::new("Suspicious_XOR_Loop", 0x1050, 0x1080));
        ann.add_iat_entry(0x3000, "ntdll.dll", "RtlAllocateHeap");
        ann.add_back_edge(0x1060, 0x1050);
        ann
    }

    #[test]
    fn test_symbol_annotation() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0x1000)];
        let at = annotator.annotate(&records);
        let anns = at.at_pc(0x1000);
        assert!(anns.iter().any(|a| matches!(&a.kind, AnnotationKind::Symbol { name, .. } if name == "main")));
    }

    #[test]
    fn test_function_boundary_annotation() {
        let annotator = build_annotator();
        let records = vec![make_bb(0, 0, 0x1000)];
        let at = annotator.annotate(&records);
        assert!(at.at_pc(0x1000).iter().any(|a| matches!(a.kind, AnnotationKind::FunctionBoundary { .. })));
    }

    #[test]
    fn test_yara_hit_annotation() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0x1060)];
        let at = annotator.annotate(&records);
        let yara = at.yara_hits();
        assert!(!yara.is_empty());
        if let AnnotationKind::YaraHit { rule, .. } = &yara[0].kind {
            assert_eq!(rule, "Suspicious_XOR_Loop");
        }
    }

    #[test]
    fn test_iat_annotation() {
        let annotator = build_annotator();
        let records = vec![make_call(0, 0, 0x1010, 0x3000), make_insn(1, 0, 0x3000)];
        let at = annotator.annotate(&records);
        let lib_calls: Vec<_> = at.annotations.iter()
            .filter(|a| matches!(a.kind, AnnotationKind::LibraryCall { .. }))
            .collect();
        assert!(!lib_calls.is_empty());
    }

    #[test]
    fn test_loop_head_annotation() {
        let annotator = build_annotator();
        let records = vec![
            make_insn(0, 0, 0x1050),
            make_insn(1, 0, 0x1060),
        ];
        let at = annotator.annotate(&records);
        let loops: Vec<_> = at.annotations.iter()
            .filter(|a| matches!(a.kind, AnnotationKind::LoopHead { .. }))
            .collect();
        assert!(!loops.is_empty());
        assert_eq!(loops[0].pc, 0x1050);
    }

    #[test]
    fn test_seen_pcs() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0xAAAA), make_insn(1, 0, 0xBBBB)];
        let at = annotator.annotate(&records);
        assert!(at.seen_pcs.contains(&0xAAAA));
        assert!(at.seen_pcs.contains(&0xBBBB));
        assert!(!at.seen_pcs.contains(&0xCCCC));
    }

    #[test]
    fn test_no_duplicate_symbol_per_pc() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0x1000), make_insn(1, 0, 0x1000)];
        let at = annotator.annotate(&records);
        let sym_count = at.at_pc(0x1000)
            .iter()
            .filter(|a| matches!(a.kind, AnnotationKind::Symbol { .. }))
            .count();
        assert_eq!(sym_count, 1);
    }

    #[test]
    fn test_covering() {
        let annotator = build_annotator();
        let records = vec![make_bb(0, 0, 0x1000)];
        let at = annotator.annotate(&records);
        // FunctionBoundary range [0x1000, 0x1100) should cover 0x1050.
        let covering = at.covering(0x1050);
        assert!(covering.iter().any(|a| matches!(a.kind, AnnotationKind::FunctionBoundary { .. })));
    }

    #[test]
    fn test_from_source() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0x1000)];
        let at = annotator.annotate(&records);
        let sym_source = AnnotationSource::SymbolFile("symbols".into());
        let sym_anns = at.from_source(&sym_source);
        assert!(!sym_anns.is_empty());
    }

    #[test]
    fn test_annotation_merger_deduplication() {
        let mut merger = AnnotationMerger::new();
        let ann1 = TraceAnnotation::new(
            0x1000,
            AnnotationKind::Symbol { name: "foo".into(), demangled: None },
            AnnotationSource::SymbolFile("a".into()),
        );
        let ann2 = TraceAnnotation::new(
            0x1000,
            AnnotationKind::Symbol { name: "foo".into(), demangled: None },
            AnnotationSource::SymbolFile("b".into()),
        );
        merger.add_source("src_a", vec![ann1]);
        merger.add_source("src_b", vec![ann2]);
        let merged = merger.merge();
        // Should be deduplicated: only one sym:foo at 0x1000.
        assert_eq!(merged.at_pc(0x1000).iter()
            .filter(|a| matches!(&a.kind, AnnotationKind::Symbol { name, .. } if name == "foo"))
            .count(), 1);
    }

    #[test]
    fn test_annotation_merger_no_deduplication() {
        let mut merger = AnnotationMerger::new().without_deduplication();
        let ann1 = TraceAnnotation::new(0x1000, AnnotationKind::Comment("a".into()), AnnotationSource::User);
        let ann2 = TraceAnnotation::new(0x1000, AnnotationKind::Comment("a".into()), AnnotationSource::User);
        merger.add_source("s1", vec![ann1]);
        merger.add_source("s2", vec![ann2]);
        let merged = merger.merge();
        assert_eq!(merged.at_pc(0x1000).len(), 2);
    }

    #[test]
    fn test_symbol_table_nearest_before() {
        let mut st = SymbolTable::new();
        st.insert(0x1000, "fn_start", None);
        st.insert(0x1100, "fn2_start", None);
        let (addr, name) = st.nearest_before(0x1050).unwrap();
        assert_eq!(addr, 0x1000);
        assert_eq!(name, "fn_start");
    }

    #[test]
    fn test_function_map_find() {
        let mut fm = FunctionMap::new();
        fm.insert(FunctionBoundary::new(0x1000, 0x1100, "foo"));
        fm.insert(FunctionBoundary::new(0x2000, 0x2100, "bar"));
        assert_eq!(fm.find(0x1050).map(|f| f.name.as_str()), Some("foo"));
        assert_eq!(fm.find(0x2000).map(|f| f.name.as_str()), Some("bar"));
        assert!(fm.find(0x3000).is_none());
    }

    #[test]
    fn test_function_map_boundary() {
        let mut fm = FunctionMap::new();
        fm.insert(FunctionBoundary::new(0x1000, 0x1100, "foo"));
        // End is exclusive: 0x1100 should NOT match.
        assert!(fm.find(0x1100).is_none());
        assert!(fm.find(0x10FF).is_some());
    }

    #[test]
    fn test_yara_hit_range() {
        let hit = YaraHitRecord::new("rule", 0x1000, 0x1010);
        assert!(hit.contains(0x1000));
        assert!(hit.contains(0x100F));
        assert!(!hit.contains(0x1010));
    }

    #[test]
    fn test_confidence_clamp() {
        let ann = TraceAnnotation::new(0, AnnotationKind::Comment("x".into()), AnnotationSource::User)
            .with_confidence(1.5);
        assert_eq!(ann.confidence, 1.0);
    }

    #[test]
    fn test_min_confidence_filter() {
        let mut annotator = TraceAnnotator::new();
        annotator.config.min_confidence = 0.9;
        // Add a loop head (confidence 0.8) — should be filtered.
        annotator.add_back_edge(0x2000, 0x1000);
        let records = vec![make_insn(0, 0, 0x1000), make_insn(1, 0, 0x2000)];
        let at = annotator.annotate(&records);
        let loops: Vec<_> = at.annotations.iter()
            .filter(|a| matches!(a.kind, AnnotationKind::LoopHead { .. }))
            .collect();
        assert!(loops.is_empty());
    }

    #[test]
    fn test_render_report() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0x1000), make_insn(1, 0, 0x2000)];
        let at = annotator.annotate(&records);
        let report = render_annotation_report(&at);
        assert!(report.contains("Trace Annotation Report"));
        assert!(report.contains("Symbols"));
    }

    #[test]
    fn test_for_record() {
        let annotator = build_annotator();
        let records = vec![make_insn(0, 0, 0x1000)];
        let at = annotator.annotate(&records);
        let anns_0 = at.for_record(0);
        assert!(!anns_0.is_empty());
        let anns_99 = at.for_record(99);
        assert!(anns_99.is_empty());
    }

    #[test]
    fn test_user_annotation_injected() {
        let mut annotator = TraceAnnotator::new();
        annotator.add_user_annotation(TraceAnnotation::new(
            0xDEAD,
            AnnotationKind::Comment("suspicious".into()),
            AnnotationSource::User,
        ));
        let records = vec![make_insn(0, 0, 0xBEEF)];
        let at = annotator.annotate(&records);
        assert!(!at.at_pc(0xDEAD).is_empty());
    }

    #[test]
    fn test_annotation_kind_display() {
        let k = AnnotationKind::Symbol { name: "foo".into(), demangled: None };
        assert_eq!(format!("{}", k), "sym:foo");
        let k2 = AnnotationKind::YaraHit { rule: "r".into(), namespace: None, tags: vec![] };
        assert_eq!(format!("{}", k2), "yara:r");
    }
}
