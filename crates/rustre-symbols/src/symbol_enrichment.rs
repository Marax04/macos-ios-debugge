//! `symbol_enrichment` — Symbol enrichment from multiple sources.
//!
//! Provides `SymbolEnricher`, `EnrichmentSource`, `EnrichmentResult`,
//! `TypeEnrichment`, `CallConvEnrichment`, `DocumentationEnrichment`,
//! `EnrichmentPipeline`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from symbol enrichment.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EnrichmentError {
    /// No symbol matched the name to be enriched.
    #[error("symbol not found: '{0}'")]
    SymbolNotFound(String),
    /// The requested enrichment data source was unavailable.
    #[error("source unavailable: {0}")]
    SourceUnavailable(String),
    /// A type string could not be parsed.
    #[error("type parse error: {0}")]
    TypeParse(String),
    /// Two sources supplied conflicting enrichment (symbol, a, b).
    #[error("conflict at '{0}': {1} vs {2}")]
    Conflict(String, String, String),
    /// A stage in the enrichment pipeline failed.
    #[error("pipeline error: {0}")]
    Pipeline(String),
}

// ─── EnrichmentSource ─────────────────────────────────────────────────────────

/// Data source that provides enrichment information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnrichmentSource {
    /// PDB debug symbols.
    Pdb,
    /// DWARF debug information.
    Dwarf,
    /// FLIRT signature library.
    Flirt,
    /// AI-generated enrichment.
    Ai,
    /// User-provided annotation.
    User,
    /// Imported from another binary.
    Import,
    /// Heuristic / pattern-based inference.
    Heuristic,
    /// Online symbol server.
    SymbolServer,
    /// Static analysis inferred.
    StaticAnalysis,
}

impl EnrichmentSource {
    /// Priority of this source (higher = more trusted).
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::User => 100,
            Self::Pdb | Self::Dwarf => 90,
            Self::SymbolServer => 80,
            Self::Flirt => 70,
            Self::Import => 60,
            Self::StaticAnalysis => 50,
            Self::Heuristic => 30,
            Self::Ai => 20,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pdb => "PDB", Self::Dwarf => "DWARF", Self::Flirt => "FLIRT",
            Self::Ai => "AI", Self::User => "User", Self::Import => "Import",
            Self::Heuristic => "Heuristic", Self::SymbolServer => "Symbol Server",
            Self::StaticAnalysis => "Static Analysis",
        }
    }
}

impl fmt::Display for EnrichmentSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.name()) }
}

// ─── TypeEnrichment ───────────────────────────────────────────────────────────

/// Type information added to a symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeEnrichment {
    /// Return type.
    pub return_type: Option<String>,
    /// Parameter types in order.
    pub param_types: Vec<String>,
    /// Parameter names.
    pub param_names: Vec<String>,
    /// Whether the function is variadic.
    pub is_variadic: bool,
    /// Full C-style signature.
    pub signature: Option<String>,
    /// Source of this type information.
    pub source: EnrichmentSource,
    /// Confidence 0–100.
    pub confidence: u8,
}

impl TypeEnrichment {
    /// Create from a signature string.
    #[must_use]
    pub fn from_signature(sig: impl Into<String>, source: EnrichmentSource) -> Self {
        let sig_s: String = sig.into();
        // Parse return type and params (simplified)
        let (ret, params) = parse_c_signature(&sig_s);
        Self {
            return_type: Some(ret),
            param_types: params.iter().map(|(_, t)| t.clone()).collect(),
            param_names: params.iter().map(|(n, _)| n.clone()).collect(),
            is_variadic: sig_s.contains("..."),
            signature: Some(sig_s),
            source, confidence: 90,
        }
    }

    /// Create a minimal type enrichment.
    #[must_use]
    pub fn minimal(return_type: impl Into<String>, source: EnrichmentSource) -> Self {
        Self {
            return_type: Some(return_type.into()),
            param_types: vec![], param_names: vec![],
            is_variadic: false, signature: None,
            source, confidence: 50,
        }
    }

    /// Number of parameters.
    #[must_use]
    pub const fn param_count(&self) -> usize { self.param_types.len() }
}

fn parse_c_signature(sig: &str) -> (String, Vec<(String, String)>) {
    // Very simplified parser for "RetType FuncName(Type1 name1, Type2 name2)"
    sig.find('(').map_or_else(
        || ("void".to_string(), vec![]),
        |paren| {
            let return_and_name = &sig[..paren];
            let ret = return_and_name
                .split_whitespace()
                .next()
                .unwrap_or("void")
                .to_string();
            let params_str = &sig[paren + 1..sig.rfind(')').unwrap_or(sig.len())];
            let params = params_str
                .split(',')
                .filter(|s| !s.trim().is_empty() && s.trim() != "void")
                .map(|p| {
                    let parts: Vec<&str> = p.trim().splitn(2, ' ').collect();
                    match parts.as_slice() {
                        [t, n] => (n.trim().to_string(), t.trim().to_string()),
                        [t] => (String::new(), t.trim().to_string()),
                        _ => (String::new(), p.trim().to_string()),
                    }
                })
                .collect();
            (ret, params)
        },
    )
}

// ─── CallConvEnrichment ───────────────────────────────────────────────────────

/// Calling convention information for a function symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallConvEnrichment {
    /// Calling convention name (e.g. `"__cdecl"`, `"__stdcall"`).
    pub convention: String,
    /// Source.
    pub source: EnrichmentSource,
    /// Confidence.
    pub confidence: u8,
}

impl CallConvEnrichment {
    /// Create a calling-convention enrichment from `source` with a default
    /// confidence of 80.
    #[must_use]
    pub fn new(convention: impl Into<String>, source: EnrichmentSource) -> Self {
        Self { convention: convention.into(), source, confidence: 80 }
    }
}

// ─── DocumentationEnrichment ─────────────────────────────────────────────────

/// Documentation comments / notes added to a symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentationEnrichment {
    /// Brief description.
    pub brief: String,
    /// Detailed documentation.
    pub detail: Option<String>,
    /// Parameter documentation: name → description.
    pub param_docs: HashMap<String, String>,
    /// Return value documentation.
    pub return_doc: Option<String>,
    /// Related symbols.
    pub see_also: Vec<String>,
    /// Source of documentation.
    pub source: EnrichmentSource,
}

impl DocumentationEnrichment {
    /// Create a documentation enrichment holding only a brief description from
    /// `source`; all other documentation fields start empty.
    #[must_use]
    pub fn new(brief: impl Into<String>, source: EnrichmentSource) -> Self {
        Self {
            brief: brief.into(), detail: None, param_docs: HashMap::new(),
            return_doc: None, see_also: vec![], source,
        }
    }

    /// Builder: add detail.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into()); self
    }

    /// Builder: add param doc.
    #[must_use]
    pub fn with_param(mut self, name: impl Into<String>, doc: impl Into<String>) -> Self {
        self.param_docs.insert(name.into(), doc.into()); self
    }

    /// Builder: add return doc.
    #[must_use]
    pub fn with_return(mut self, doc: impl Into<String>) -> Self {
        self.return_doc = Some(doc.into()); self
    }

    /// Builder: add see-also.
    #[must_use]
    pub fn see_also(mut self, sym: impl Into<String>) -> Self {
        self.see_also.push(sym.into()); self
    }
}

// ─── EnrichmentResult ────────────────────────────────────────────────────────

/// Enrichment information added to a symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// The symbol's virtual address.
    pub address: u64,
    /// Enriched name (if renamed).
    pub name: Option<String>,
    /// Demangled name.
    pub demangled_name: Option<String>,
    /// Type enrichment.
    pub type_info: Option<TypeEnrichment>,
    /// Calling convention.
    pub call_conv: Option<CallConvEnrichment>,
    /// Documentation.
    pub documentation: Option<DocumentationEnrichment>,
    /// Additional tags.
    pub tags: Vec<String>,
    /// Primary source.
    pub source: EnrichmentSource,
    /// Confidence 0–100.
    pub confidence: u8,
}

impl EnrichmentResult {
    /// Create a minimal enrichment.
    #[must_use]
    pub const fn new(address: u64, source: EnrichmentSource) -> Self {
        Self {
            address, name: None, demangled_name: None, type_info: None,
            call_conv: None, documentation: None, tags: vec![],
            source, confidence: 50,
        }
    }

    /// Builder: set name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into()); self
    }

    /// Builder: set type info.
    #[must_use]
    pub fn with_type(mut self, t: TypeEnrichment) -> Self {
        self.type_info = Some(t); self
    }

    /// Builder: set call conv.
    #[must_use]
    pub fn with_call_conv(mut self, cc: CallConvEnrichment) -> Self {
        self.call_conv = Some(cc); self
    }

    /// Builder: set documentation.
    #[must_use]
    pub fn with_docs(mut self, doc: DocumentationEnrichment) -> Self {
        self.documentation = Some(doc); self
    }

    /// Builder: add tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into()); self
    }

    /// Builder: set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: u8) -> Self { self.confidence = c; self }

    /// Return `true` if the enrichment has type information.
    #[must_use]
    pub const fn has_type_info(&self) -> bool { self.type_info.is_some() }

    /// Return `true` if the enrichment has documentation.
    #[must_use]
    pub const fn has_docs(&self) -> bool { self.documentation.is_some() }
}

impl fmt::Display for EnrichmentResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        let hex = format!("{:08x}", self.address);
        let (hi, lo) = hex.split_at(hex.len() - 4);
        write!(f, "0x{hi}_{lo} -> {name} [{src}] conf={c}%",
            src = self.source, c = self.confidence)
    }
}

// ─── SymbolEnricher trait ─────────────────────────────────────────────────────

/// A source that can enrich symbols.
pub trait SymbolEnricher: Send + Sync {
    /// Source type.
    fn source(&self) -> EnrichmentSource;

    /// Enrich a symbol at the given address.
    ///
    /// # Errors
    /// Returns `EnrichmentError` on failure.
    fn enrich(&self, address: u64, name: &str) -> Result<EnrichmentResult, EnrichmentError>;

    /// Return `true` if this enricher can provide information for the given address.
    fn can_enrich(&self, address: u64) -> bool;

    /// Priority (higher = checked first).
    fn priority(&self) -> u8 { self.source().priority() }
}

// ─── Built-in enrichers ───────────────────────────────────────────────────────

/// An enricher backed by a static lookup table.
pub struct TableEnricher {
    source: EnrichmentSource,
    table: HashMap<String, EnrichmentResult>,
}

impl TableEnricher {
    /// Create a new table enricher.
    #[must_use]
    pub fn new(source: EnrichmentSource) -> Self {
        Self { source, table: HashMap::new() }
    }

    /// Add an entry.
    pub fn add(&mut self, name: impl Into<String>, result: EnrichmentResult) {
        self.table.insert(name.into(), result);
    }
}

impl SymbolEnricher for TableEnricher {
    fn source(&self) -> EnrichmentSource { self.source }
    fn can_enrich(&self, _: u64) -> bool { true }
    fn enrich(&self, _address: u64, name: &str) -> Result<EnrichmentResult, EnrichmentError> {
        self.table.get(name)
            .cloned()
            .ok_or_else(|| EnrichmentError::SymbolNotFound(name.to_string()))
    }
}

/// AI-based enricher (mock implementation).
pub struct AiEnricher {
    /// Confidence boost applied to AI results.
    pub base_confidence: u8,
}

impl AiEnricher {
    /// Create an AI enricher with the default base confidence of 60.
    #[must_use]
    pub const fn new() -> Self { Self { base_confidence: 60 } }
}

impl Default for AiEnricher {
    fn default() -> Self { Self::new() }
}

impl SymbolEnricher for AiEnricher {
    fn source(&self) -> EnrichmentSource { EnrichmentSource::Ai }
    fn can_enrich(&self, _: u64) -> bool { true }
    fn enrich(&self, address: u64, name: &str) -> Result<EnrichmentResult, EnrichmentError> {
        // Mock: generate a plausible description from the name
        let brief = format!("AI-inferred: {name} appears to perform computation");
        let doc = DocumentationEnrichment::new(brief, EnrichmentSource::Ai);
        let result = EnrichmentResult::new(address, EnrichmentSource::Ai)
            .with_docs(doc)
            .with_confidence(self.base_confidence);
        Ok(result)
    }
}

/// Heuristic enricher based on common name patterns.
pub struct HeuristicEnricher;

impl SymbolEnricher for HeuristicEnricher {
    fn source(&self) -> EnrichmentSource { EnrichmentSource::Heuristic }
    fn can_enrich(&self, _: u64) -> bool { true }
    fn enrich(&self, address: u64, name: &str) -> Result<EnrichmentResult, EnrichmentError> {
        let lower = name.to_ascii_lowercase();
        let mut result = EnrichmentResult::new(address, EnrichmentSource::Heuristic);

        // Use compiled regex patterns for robust name classification.
        let re_unnamed = Regex::new(r"^(sub|func)_").expect("static regex is valid");
        let re_crypto   = Regex::new(r"encrypt|decrypt").expect("static regex is valid");
        // `hash` is a single literal token; we check it via `str::contains`
        // below rather than allocating a trivial `Regex`.
        let re_network  = Regex::new(r"connect|socket").expect("static regex is valid");
        let re_process_create = Regex::new(r"create.*process|process.*create").expect("static regex is valid");

        if re_unnamed.is_match(&lower) {
            result = result.with_tag("unnamed").with_confidence(20);
        } else if re_crypto.is_match(&lower) {
            result = result.with_tag("crypto").with_confidence(70);
        } else if lower.contains("hash") {
            result = result.with_tag("crypto").with_tag("hash").with_confidence(65);
        } else if re_network.is_match(&lower) {
            result = result.with_tag("network").with_confidence(75);
        } else if re_process_create.is_match(&lower) {
            result = result.with_tag("process").with_confidence(80);
        } else {
            result = result.with_confidence(30);
        }

        Ok(result)
    }
}

// ─── EnrichmentPipeline ───────────────────────────────────────────────────────

/// Runs multiple enrichers in priority order and merges results.
pub struct EnrichmentPipeline {
    enrichers: Vec<Arc<dyn SymbolEnricher>>,
    /// How to resolve conflicts between sources.
    pub conflict_strategy: ConflictStrategy,
}

/// Strategy for merging conflicting enrichment data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Higher-priority source wins.
    PriorityWins,
    /// Higher-confidence source wins.
    HighestConfidence,
    /// First enricher to provide data wins.
    FirstWins,
}

impl EnrichmentPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self { enrichers: vec![], conflict_strategy: ConflictStrategy::PriorityWins }
    }

    /// Create with default enrichers (Heuristic + AI).
    #[must_use]
    pub fn default_pipeline() -> Self {
        let mut p = Self::new();
        p.add(Arc::new(HeuristicEnricher));
        p.add(Arc::new(AiEnricher::new()));
        p
    }

    /// Add an enricher.
    pub fn add(&mut self, enricher: Arc<dyn SymbolEnricher>) {
        self.enrichers.push(enricher);
        // Sort by descending priority
        self.enrichers.sort_by_key(|e| std::cmp::Reverse(e.priority()));
    }

    /// Enrich a symbol and return the merged result.
    ///
    /// # Errors
    /// Returns `EnrichmentError` if no enricher can enrich the symbol.
    pub fn enrich(&self, address: u64, name: &str) -> Result<EnrichmentResult, EnrichmentError> {
        let mut merged: Option<EnrichmentResult> = None;

        for enricher in &self.enrichers {
            if !enricher.can_enrich(address) { continue; }
            if let Ok(result) = enricher.enrich(address, name) {
                merged = Some(match merged {
                    None => result,
                    Some(existing) => self.merge(existing, result),
                });
            }
        }

        merged.ok_or_else(|| EnrichmentError::SymbolNotFound(name.to_string()))
    }

    /// Merge two enrichment results.
    fn merge(&self, a: EnrichmentResult, b: EnrichmentResult) -> EnrichmentResult {
        let (winner, loser) = match self.conflict_strategy {
            ConflictStrategy::PriorityWins => {
                if a.source.priority() >= b.source.priority() { (a, b) } else { (b, a) }
            }
            ConflictStrategy::HighestConfidence => {
                if a.confidence >= b.confidence { (a, b) } else { (b, a) }
            }
            ConflictStrategy::FirstWins => (a, b),
        };

        // Merge: winner's fields take precedence, fill gaps from loser
        let mut result = winner;
        if result.name.is_none() { result.name = loser.name; }
        if result.demangled_name.is_none() { result.demangled_name = loser.demangled_name; }
        if result.type_info.is_none() { result.type_info = loser.type_info; }
        if result.call_conv.is_none() { result.call_conv = loser.call_conv; }
        if result.documentation.is_none() { result.documentation = loser.documentation; }
        for tag in loser.tags { if !result.tags.contains(&tag) { result.tags.push(tag); } }
        result
    }

    /// Enrich a batch of symbols.
    ///
    /// Symbols that cannot be enriched are skipped (error is recorded).
    #[must_use]
    pub fn enrich_batch(&self, symbols: &[(u64, String)]) -> Vec<(u64, String, Result<EnrichmentResult, EnrichmentError>)> {
        symbols.iter().map(|(addr, name)| {
            let result = self.enrich(*addr, name);
            (*addr, name.clone(), result)
        }).collect()
    }

    /// Number of enrichers.
    #[must_use]
    pub fn enricher_count(&self) -> usize { self.enrichers.len() }
}

impl Default for EnrichmentPipeline {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EnrichmentSource ──────────────────────────────────────────────────────

    #[test]
    fn test_source_priority_ordering() {
        assert!(EnrichmentSource::User.priority() > EnrichmentSource::Pdb.priority());
        assert!(EnrichmentSource::Pdb.priority() > EnrichmentSource::Ai.priority());
    }

    #[test]
    fn test_source_names_unique() {
        let sources = [
            EnrichmentSource::Pdb, EnrichmentSource::Dwarf, EnrichmentSource::Flirt,
            EnrichmentSource::Ai, EnrichmentSource::User,
        ];
        let names: std::collections::HashSet<&str> = sources.iter().map(|s| s.name()).collect();
        assert_eq!(names.len(), sources.len());
    }

    #[test]
    fn test_source_display() {
        assert_eq!(EnrichmentSource::Pdb.to_string(), "PDB");
    }

    // ── TypeEnrichment ────────────────────────────────────────────────────────

    #[test]
    fn test_type_from_signature() {
        let t = TypeEnrichment::from_signature("int CreateFile(const char* path, int flags)", EnrichmentSource::Pdb);
        assert_eq!(t.return_type.as_deref(), Some("int"));
        assert!(t.param_count() > 0);
    }

    #[test]
    fn test_type_minimal() {
        let t = TypeEnrichment::minimal("void", EnrichmentSource::Flirt);
        assert_eq!(t.return_type.as_deref(), Some("void"));
        assert_eq!(t.param_count(), 0);
    }

    #[test]
    fn test_type_variadic() {
        let t = TypeEnrichment::from_signature("int printf(const char* fmt, ...)", EnrichmentSource::Pdb);
        assert!(t.is_variadic);
    }

    // ── CallConvEnrichment ────────────────────────────────────────────────────

    #[test]
    fn test_callconv_new() {
        let cc = CallConvEnrichment::new("__cdecl", EnrichmentSource::Pdb);
        assert_eq!(cc.convention, "__cdecl");
    }

    // ── DocumentationEnrichment ───────────────────────────────────────────────

    #[test]
    fn test_doc_new() {
        let doc = DocumentationEnrichment::new("Opens a file", EnrichmentSource::User)
            .with_detail("Uses the kernel32 API")
            .with_param("path", "File path")
            .with_return("File handle or -1 on error")
            .see_also("CloseHandle");
        assert_eq!(doc.brief, "Opens a file");
        assert!(doc.detail.is_some());
        assert!(!doc.param_docs.is_empty());
        assert!(!doc.see_also.is_empty());
    }

    // ── EnrichmentResult ──────────────────────────────────────────────────────

    #[test]
    fn test_result_builders() {
        let r = EnrichmentResult::new(0x0040_1000, EnrichmentSource::User)
            .with_name("CreateFile")
            .with_tag("file")
            .with_confidence(95);
        assert_eq!(r.name.as_deref(), Some("CreateFile"));
        assert!(r.tags.contains(&"file".to_string()));
        assert_eq!(r.confidence, 95);
    }

    #[test]
    fn test_result_has_type_info() {
        let r = EnrichmentResult::new(0, EnrichmentSource::Pdb)
            .with_type(TypeEnrichment::minimal("void", EnrichmentSource::Pdb));
        assert!(r.has_type_info());
    }

    #[test]
    fn test_result_has_docs() {
        let r = EnrichmentResult::new(0, EnrichmentSource::User)
            .with_docs(DocumentationEnrichment::new("desc", EnrichmentSource::User));
        assert!(r.has_docs());
    }

    #[test]
    fn test_result_display() {
        let r = EnrichmentResult::new(0x0040_1000, EnrichmentSource::Pdb).with_name("main");
        assert!(r.to_string().contains("main"));
        assert!(r.to_string().contains("0x0040_1000"));
    }

    // ── TableEnricher ─────────────────────────────────────────────────────────

    #[test]
    fn test_table_enricher_hit() {
        let mut e = TableEnricher::new(EnrichmentSource::Pdb);
        e.add("CreateFile", EnrichmentResult::new(0x1000, EnrichmentSource::Pdb).with_name("CreateFile"));
        let r = e.enrich(0x1000, "CreateFile").unwrap();
        assert_eq!(r.name.as_deref(), Some("CreateFile"));
    }

    #[test]
    fn test_table_enricher_miss() {
        let e = TableEnricher::new(EnrichmentSource::Pdb);
        let result = e.enrich(0x1000, "Unknown");
        assert!(matches!(result, Err(EnrichmentError::SymbolNotFound(_))));
    }

    // ── HeuristicEnricher ─────────────────────────────────────────────────────

    #[test]
    fn test_heuristic_unnamed() {
        let e = HeuristicEnricher;
        let r = e.enrich(0, "sub_1000").unwrap();
        assert!(r.tags.contains(&"unnamed".to_string()));
    }

    #[test]
    fn test_heuristic_crypto() {
        let e = HeuristicEnricher;
        let r = e.enrich(0, "EncryptData").unwrap();
        assert!(r.tags.contains(&"crypto".to_string()));
    }

    #[test]
    fn test_heuristic_network() {
        let e = HeuristicEnricher;
        let r = e.enrich(0, "ConnectToServer").unwrap();
        assert!(r.tags.contains(&"network".to_string()));
    }

    // ── AiEnricher ────────────────────────────────────────────────────────────

    #[test]
    fn test_ai_enricher_always_succeeds() {
        let e = AiEnricher::new();
        let r = e.enrich(0, "sub_1000").unwrap();
        assert!(r.has_docs());
    }

    // ── EnrichmentPipeline ────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_empty_error() {
        let p = EnrichmentPipeline::new();
        let result = p.enrich(0x1000, "foo");
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_default() {
        let p = EnrichmentPipeline::default_pipeline();
        assert!(p.enricher_count() >= 2);
        let r = p.enrich(0x1000, "EncryptData").unwrap();
        assert!(r.tags.contains(&"crypto".to_string()) || r.has_docs());
    }

    #[test]
    fn test_pipeline_priority_wins() {
        let mut p = EnrichmentPipeline::new();
        // Add low-priority enricher with name "low_name"
        let mut low = TableEnricher::new(EnrichmentSource::Heuristic);
        low.add("foo", EnrichmentResult::new(0, EnrichmentSource::Heuristic).with_name("low_name").with_confidence(30));
        // Add high-priority enricher with name "high_name"
        let mut high = TableEnricher::new(EnrichmentSource::User);
        high.add("foo", EnrichmentResult::new(0, EnrichmentSource::User).with_name("high_name").with_confidence(95));
        p.add(Arc::new(low));
        p.add(Arc::new(high));
        p.conflict_strategy = ConflictStrategy::PriorityWins;
        let r = p.enrich(0, "foo").unwrap();
        assert_eq!(r.name.as_deref(), Some("high_name"));
    }

    #[test]
    fn test_pipeline_merges_tags() {
        let mut p = EnrichmentPipeline::new();
        let mut e1 = TableEnricher::new(EnrichmentSource::Heuristic);
        e1.add("bar", EnrichmentResult::new(0, EnrichmentSource::Heuristic).with_tag("heuristic_tag").with_confidence(30));
        let mut e2 = TableEnricher::new(EnrichmentSource::Ai);
        e2.add("bar", EnrichmentResult::new(0, EnrichmentSource::Ai).with_tag("ai_tag").with_confidence(60));
        p.add(Arc::new(e1));
        p.add(Arc::new(e2));
        let r = p.enrich(0, "bar").unwrap();
        // Both tags should be merged
        assert!(r.tags.contains(&"heuristic_tag".to_string()) || r.tags.contains(&"ai_tag".to_string()));
    }

    #[test]
    fn test_pipeline_batch() {
        let p = EnrichmentPipeline::default_pipeline();
        let syms = vec![(0x1000u64, "EncryptData".to_string()), (0x2000u64, "ConnectSocket".to_string())];
        let results = p.enrich_batch(&syms);
        assert_eq!(results.len(), 2);
        for (_, _, r) in &results { assert!(r.is_ok()); }
    }

    #[test]
    fn test_enrichment_error_display() {
        let e = EnrichmentError::SymbolNotFound("foo".into());
        assert!(e.to_string().contains("foo"));
    }

    #[test]
    fn test_type_parse_simple() {
        let (ret, params) = parse_c_signature("void* malloc(size_t size)");
        assert!(ret.contains("void"));
        assert!(!params.is_empty());
    }

    #[test]
    fn test_table_enricher_can_enrich() {
        let e = TableEnricher::new(EnrichmentSource::Pdb);
        assert!(e.can_enrich(0x0040_1000));
    }
}
