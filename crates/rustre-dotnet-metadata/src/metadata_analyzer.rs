//! Metadata obfuscation analyzer — `MetadataAnalyzer` and detector types.
//!
//! Identifies obfuscated code patterns such as encrypted strings, control-flow
//! obfuscation, renamed symbols, proxy methods, code inlining artefacts,
//! and known obfuscator signatures.

use std::collections::HashMap;
use std::fmt;

// ─── ObfuscationConfidence ────────────────────────────────────────────────────

/// Confidence level of an obfuscation detection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObfuscationConfidence {
    #[default]
    Low,
    Medium,
    High,
}

impl fmt::Display for ObfuscationConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

// ─── StringEncryption ────────────────────────────────────────────────────────

/// A detected encrypted string literal.
#[derive(Debug, Clone)]
pub struct StringEncryption {
    /// IL offset of the decrypt call.
    pub il_offset: u32,
    /// Type name of the method that was detected.
    pub enclosing_type: String,
    /// Method name where the encrypted string was found.
    pub enclosing_method: String,
    /// The encrypted bytes as they appear in the assembly.
    pub encrypted_bytes: Vec<u8>,
    /// Decrypted plaintext, if recoverable.
    pub decrypted: Option<String>,
    /// Decryption method called.
    pub decrypt_method: String,
    pub confidence: ObfuscationConfidence,
}

impl StringEncryption {
    #[must_use]
    pub fn new(
        il_offset: u32,
        enclosing_type: impl Into<String>,
        enclosing_method: impl Into<String>,
        decrypt_method: impl Into<String>,
    ) -> Self {
        Self {
            il_offset,
            enclosing_type: enclosing_type.into(),
            enclosing_method: enclosing_method.into(),
            encrypted_bytes: Vec::new(),
            decrypted: None,
            decrypt_method: decrypt_method.into(),
            confidence: ObfuscationConfidence::High,
        }
    }

    /// Returns `true` if the string was successfully decrypted.
    #[must_use]
    pub const fn is_decrypted(&self) -> bool {
        self.decrypted.is_some()
    }
}

// ─── ControlFlowObfuscation ───────────────────────────────────────────────────

/// Kind of control-flow obfuscation technique detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CfoKind {
    /// Opaque predicates that always evaluate to the same value.
    OpaquePredicate,
    /// Junk/unreachable code blocks inserted to confuse decompilers.
    JunkCode,
    /// Switch-table based dispatcher (often produced by `ConfuserEx` etc.).
    SwitchDispatcher,
    /// Fake exception handlers that never execute but add noise.
    FakeExceptionHandler,
    /// Conditional jump replaced with an unconditional jump + junk block.
    UnreachableBranch,
}

impl fmt::Display for CfoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpaquePredicate => write!(f, "OpaquePredicate"),
            Self::JunkCode => write!(f, "JunkCode"),
            Self::SwitchDispatcher => write!(f, "SwitchDispatcher"),
            Self::FakeExceptionHandler => write!(f, "FakeExceptionHandler"),
            Self::UnreachableBranch => write!(f, "UnreachableBranch"),
        }
    }
}

/// A detected control-flow obfuscation instance.
#[derive(Debug, Clone)]
pub struct ControlFlowObfuscation {
    pub kind: CfoKind,
    pub il_offset: u32,
    pub method_token: u32,
    pub method_name: String,
    /// Number of extra branches or junk instructions introduced.
    pub complexity_increase: u32,
    pub confidence: ObfuscationConfidence,
}

impl ControlFlowObfuscation {
    #[must_use]
    pub fn new(
        kind: CfoKind,
        il_offset: u32,
        method_token: u32,
        method_name: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            il_offset,
            method_token,
            method_name: method_name.into(),
            complexity_increase: 0,
            confidence: ObfuscationConfidence::Medium,
        }
    }
}

// ─── RenameObfuscation ────────────────────────────────────────────────────────

/// A renamed symbol detected via heuristic analysis.
#[derive(Debug, Clone)]
pub struct RenameObfuscation {
    /// The renamed identifier.
    pub name: String,
    /// The metadata token of this identifier.
    pub token: u32,
    /// Whether the identifier is a type, method, field, property, or parameter.
    pub symbol_kind: String,
    /// Heuristic reason for suspicion (e.g. "single-char name", "non-printable char").
    pub reason: String,
    pub confidence: ObfuscationConfidence,
}

impl RenameObfuscation {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        token: u32,
        symbol_kind: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            token,
            symbol_kind: symbol_kind.into(),
            reason: reason.into(),
            confidence: ObfuscationConfidence::Medium,
        }
    }

    /// Heuristic check: returns `true` if the name looks obfuscated.
    #[must_use]
    pub fn looks_obfuscated(name: &str) -> bool {
        if name.is_empty() {
            return true;
        }
        // Single visible char or starts with non-alphabetic non-underscore.
        if name.chars().count() <= 2 {
            return true;
        }
        // Contains non-printable / non-ASCII characters.
        if name.chars().any(|c| !c.is_ascii() || c.is_control()) {
            return true;
        }
        // All characters are the same (e.g. "aaaa").
        let len = name.len();
        if len > 3 {
            let first = name.as_bytes()[0];
            if name.bytes().all(|b| b == first) {
                return true;
            }
        }
        false
    }
}

// ─── ProxyMethod ─────────────────────────────────────────────────────────────

/// A proxy method — a trivial wrapper that calls another method with no other logic.
#[derive(Debug, Clone)]
pub struct ProxyMethod {
    /// Token of the proxy method.
    pub proxy_token: u32,
    /// Name of the proxy method.
    pub proxy_name: String,
    /// Type containing the proxy.
    pub proxy_type: String,
    /// Token of the real method being delegated to.
    pub real_method_token: u32,
    /// Name of the real method.
    pub real_method_name: String,
    /// Whether the proxy does any argument shuffling.
    pub is_direct_pass_through: bool,
    pub confidence: ObfuscationConfidence,
}

impl ProxyMethod {
    #[must_use]
    pub fn new(
        proxy_token: u32,
        proxy_name: impl Into<String>,
        proxy_type: impl Into<String>,
    ) -> Self {
        Self {
            proxy_token,
            proxy_name: proxy_name.into(),
            proxy_type: proxy_type.into(),
            real_method_token: 0,
            real_method_name: String::new(),
            is_direct_pass_through: false,
            confidence: ObfuscationConfidence::High,
        }
    }
}

// ─── CodeInlining ─────────────────────────────────────────────────────────────

/// Detected inlining artefact (code from one method duplicated into another).
#[derive(Debug, Clone)]
pub struct CodeInlining {
    /// Token of the method where inlining was detected.
    pub call_site_token: u32,
    /// Token of the method that was inlined.
    pub inlined_method_token: u32,
    /// Name of the inlined method.
    pub inlined_method_name: String,
    /// Number of IL instructions inlined.
    pub inlined_instruction_count: u32,
    /// IL offset in the call site where the inlined code begins.
    pub start_offset: u32,
    pub confidence: ObfuscationConfidence,
}

impl CodeInlining {
    #[must_use]
    pub fn new(
        call_site_token: u32,
        inlined_method_token: u32,
        inlined_method_name: impl Into<String>,
        start_offset: u32,
    ) -> Self {
        Self {
            call_site_token,
            inlined_method_token,
            inlined_method_name: inlined_method_name.into(),
            inlined_instruction_count: 0,
            start_offset,
            confidence: ObfuscationConfidence::Medium,
        }
    }
}

// ─── ObfuscatorSignature ──────────────────────────────────────────────────────

/// A known obfuscator identified from assembly-level signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KnownObfuscator {
    /// `ConfuserEx` or its derivatives.
    ConfuserEx,
    /// Dotfuscator (`PreEmptive` Solutions).
    Dotfuscator,
    /// Eazfuscator.
    Eazfuscator,
    /// .NET Reactor.
    DotNetReactor,
    /// `SmartAssembly`.
    SmartAssembly,
    /// Babel.NET.
    BabelNet,
    /// de4dot-compatible obfuscator.
    Unknown(String),
}

impl fmt::Display for KnownObfuscator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfuserEx => write!(f, "ConfuserEx"),
            Self::Dotfuscator => write!(f, "Dotfuscator"),
            Self::Eazfuscator => write!(f, "Eazfuscator"),
            Self::DotNetReactor => write!(f, ".NET Reactor"),
            Self::SmartAssembly => write!(f, "SmartAssembly"),
            Self::BabelNet => write!(f, "Babel.NET"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

/// Evidence that a known obfuscator was used on this assembly.
#[derive(Debug, Clone)]
pub struct ObfuscatorSignature {
    pub obfuscator: KnownObfuscator,
    /// Version string if detectable.
    pub version: Option<String>,
    /// Specific indicators that triggered detection.
    pub indicators: Vec<String>,
    pub confidence: ObfuscationConfidence,
}

impl ObfuscatorSignature {
    #[must_use]
    pub const fn new(obfuscator: KnownObfuscator, confidence: ObfuscationConfidence) -> Self {
        Self {
            obfuscator,
            version: None,
            indicators: Vec::new(),
            confidence,
        }
    }

    pub fn add_indicator(&mut self, indicator: impl Into<String>) {
        self.indicators.push(indicator.into());
    }
}

// ─── ObfuscatedCode ───────────────────────────────────────────────────────────

/// Aggregated detection result for a single assembly.
#[derive(Debug, Default, Clone)]
pub struct ObfuscatedCode {
    /// Detected encrypted string sites.
    pub string_encryptions: Vec<StringEncryption>,
    /// Detected control-flow obfuscations.
    pub control_flow: Vec<ControlFlowObfuscation>,
    /// Renamed symbols.
    pub renamed_symbols: Vec<RenameObfuscation>,
    /// Detected proxy methods.
    pub proxy_methods: Vec<ProxyMethod>,
    /// Detected code inlining artefacts.
    pub code_inlinings: Vec<CodeInlining>,
    /// Detected obfuscator signatures.
    pub signatures: Vec<ObfuscatorSignature>,
}

impl ObfuscatedCode {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if any obfuscation was detected.
    #[must_use]
    pub const fn is_obfuscated(&self) -> bool {
        !self.string_encryptions.is_empty()
            || !self.control_flow.is_empty()
            || !self.renamed_symbols.is_empty()
            || !self.proxy_methods.is_empty()
            || !self.code_inlinings.is_empty()
            || !self.signatures.is_empty()
    }

    /// Total number of individual obfuscation findings.
    #[must_use]
    pub const fn total_findings(&self) -> usize {
        self.string_encryptions.len()
            + self.control_flow.len()
            + self.renamed_symbols.len()
            + self.proxy_methods.len()
            + self.code_inlinings.len()
            + self.signatures.len()
    }

    /// Return the highest-confidence finding, or `None` if no findings.
    #[must_use]
    pub fn max_confidence(&self) -> Option<ObfuscationConfidence> {
        let mut max = None::<ObfuscationConfidence>;
        let update = |m: &mut Option<ObfuscationConfidence>, c: ObfuscationConfidence| {
            *m = Some(m.map_or(c, |prev| prev.max(c)));
        };
        for f in &self.string_encryptions {
            update(&mut max, f.confidence);
        }
        for f in &self.control_flow {
            update(&mut max, f.confidence);
        }
        for f in &self.renamed_symbols {
            update(&mut max, f.confidence);
        }
        for f in &self.proxy_methods {
            update(&mut max, f.confidence);
        }
        for f in &self.code_inlinings {
            update(&mut max, f.confidence);
        }
        for f in &self.signatures {
            update(&mut max, f.confidence);
        }
        max
    }
}

// ─── MetadataAnalyzer ─────────────────────────────────────────────────────────

/// Analyzes assembly metadata for obfuscation patterns and anomalies.
#[derive(Debug, Default)]
pub struct MetadataAnalyzer {
    /// Per-assembly analysis results, keyed by assembly name.
    results: HashMap<String, ObfuscatedCode>,
    /// Thresholds and configuration.
    pub min_confidence: ObfuscationConfidence,
    /// Whether to attempt heuristic name analysis.
    pub analyze_names: bool,
    /// Whether to detect proxy methods.
    pub detect_proxy_methods: bool,
}

impl MetadataAnalyzer {
    /// Create a new `MetadataAnalyzer` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            min_confidence: ObfuscationConfidence::Low,
            analyze_names: true,
            detect_proxy_methods: true,
        }
    }

    // ── Ingestion ──────────────────────────────────────────────────────────────

    /// Register or update the analysis result for an assembly.
    pub fn set_result(&mut self, assembly: impl Into<String>, result: ObfuscatedCode) {
        self.results.insert(assembly.into(), result);
    }

    /// Get the analysis result for an assembly.
    #[must_use]
    pub fn get_result(&self, assembly: &str) -> Option<&ObfuscatedCode> {
        self.results.get(assembly)
    }

    /// Return a mutable reference to create/extend a result.
    pub fn get_or_create(&mut self, assembly: impl Into<String>) -> &mut ObfuscatedCode {
        self.results.entry(assembly.into()).or_default()
    }

    // ── Aggregate queries ──────────────────────────────────────────────────────

    /// Return all assemblies that appear to be obfuscated.
    #[must_use]
    pub fn obfuscated_assemblies(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|(_, r)| r.is_obfuscated())
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Return all detected obfuscator signatures across all assemblies.
    #[must_use]
    pub fn all_signatures(&self) -> Vec<(&str, &ObfuscatorSignature)> {
        self.results
            .iter()
            .flat_map(|(name, r)| r.signatures.iter().map(move |s| (name.as_str(), s)))
            .collect()
    }

    /// Return all encrypted string sites across all assemblies.
    #[must_use]
    pub fn all_encrypted_strings(&self) -> Vec<(&str, &StringEncryption)> {
        self.results
            .iter()
            .flat_map(|(name, r)| r.string_encryptions.iter().map(move |e| (name.as_str(), e)))
            .collect()
    }

    /// Return all proxy methods across all assemblies.
    #[must_use]
    pub fn all_proxy_methods(&self) -> Vec<(&str, &ProxyMethod)> {
        self.results
            .iter()
            .flat_map(|(name, r)| r.proxy_methods.iter().map(move |p| (name.as_str(), p)))
            .collect()
    }

    /// Total findings across all assemblies.
    #[must_use]
    pub fn total_findings(&self) -> usize {
        self.results
            .values()
            .map(ObfuscatedCode::total_findings)
            .sum()
    }

    /// Return the number of assemblies analyzed.
    #[must_use]
    pub fn assembly_count(&self) -> usize {
        self.results.len()
    }

    // ── Heuristic analysis helpers ─────────────────────────────────────────────

    /// Analyze a list of type names and flag likely renamed ones.
    #[must_use]
    pub fn detect_renamed_types(&self, type_names: &[(u32, &str)]) -> Vec<RenameObfuscation> {
        type_names
            .iter()
            .filter(|(_, name)| RenameObfuscation::looks_obfuscated(name))
            .map(|(token, name)| {
                RenameObfuscation::new(*name, *token, "type", "heuristic name check")
            })
            .collect()
    }

    /// Scan method IL bytes for common proxy-method patterns.
    ///
    /// A proxy method is identified as: `ldarg.0, ldarg.1, ..., call <token>, ret` with no
    /// other instructions.
    #[must_use]
    pub fn detect_proxy_method(
        &self,
        method_token: u32,
        method_name: &str,
        method_type: &str,
        il: &[u8],
    ) -> Option<ProxyMethod> {
        if il.is_empty() {
            return None;
        }
        // Simple heuristic: all bytes up to the last `ret` are `ldarg.*` or `call` instructions.
        // We look for: {ldarg*, nop*} + call(4-byte token) + ret
        let last = *il.last()?;
        if last != 0x2A {
            return None;
        } // must end with ret
        
        let mut pos = 0;
        let mut call_token = None;
        while pos < il.len() - 1 {
            match il[pos] {
                0x00 | 0x02 | 0x03 | 0x04 | 0x05 => {
                    pos += 1;
                }
                0x0E => {
                    if pos + 2 > il.len() - 1 {
                        return None;
                    }
                    pos += 2;
                }
                0x28 => {
                    if pos + 5 > il.len() - 1 {
                        return None;
                    }
                    let token = u32::from_le_bytes([
                        il[pos + 1],
                        il[pos + 2],
                        il[pos + 3],
                        il[pos + 4],
                    ]);
                    call_token = Some(token);
                    pos += 5;
                }
                _ => return None,
            }
        }

        if il.len() >= 6 {
            let mut pm = ProxyMethod::new(method_token, method_name, method_type);
            if let Some(token) = call_token {
                pm.real_method_token = token;
            }
            pm.is_direct_pass_through = true;
            pm.confidence = ObfuscationConfidence::High;
            return Some(pm);
        }
        None
    }

    /// Quick scan of an obfuscator signature by assembly-level attributes.
    #[must_use]
    pub fn detect_signature_from_attributes(
        &self,
        attribute_types: &[String],
    ) -> Option<ObfuscatorSignature> {
        for attr in attribute_types {
            let lower = attr.to_ascii_lowercase();
            if lower.contains("confuserex") || lower.contains("confuser") {
                let mut sig = ObfuscatorSignature::new(
                    KnownObfuscator::ConfuserEx,
                    ObfuscationConfidence::High,
                );
                sig.add_indicator(format!("custom attribute: {attr}"));
                return Some(sig);
            }
            if lower.contains("dotfuscator") {
                let mut sig = ObfuscatorSignature::new(
                    KnownObfuscator::Dotfuscator,
                    ObfuscationConfidence::High,
                );
                sig.add_indicator(format!("custom attribute: {attr}"));
                return Some(sig);
            }
            if lower.contains("eazfuscator") {
                let mut sig = ObfuscatorSignature::new(
                    KnownObfuscator::Eazfuscator,
                    ObfuscationConfidence::High,
                );
                sig.add_indicator(format!("custom attribute: {attr}"));
                return Some(sig);
            }
        }
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ObfuscationConfidence ─────────────────────────────────────────────────

    #[test]
    fn confidence_ordering() {
        assert!(ObfuscationConfidence::High > ObfuscationConfidence::Medium);
        assert!(ObfuscationConfidence::Medium > ObfuscationConfidence::Low);
    }

    #[test]
    fn confidence_display() {
        assert_eq!(ObfuscationConfidence::High.to_string(), "high");
        assert_eq!(ObfuscationConfidence::Low.to_string(), "low");
    }

    // ── StringEncryption ──────────────────────────────────────────────────────

    #[test]
    fn string_encryption_not_decrypted() {
        let s = StringEncryption::new(0x10, "NS.T", "Method", "Decrypt");
        assert!(!s.is_decrypted());
    }

    #[test]
    fn string_encryption_decrypted() {
        let mut s = StringEncryption::new(0x10, "NS.T", "Method", "Decrypt");
        s.decrypted = Some("hello world".into());
        assert!(s.is_decrypted());
    }

    // ── ControlFlowObfuscation ────────────────────────────────────────────────

    #[test]
    fn cfo_kind_display() {
        assert_eq!(CfoKind::OpaquePredicate.to_string(), "OpaquePredicate");
        assert_eq!(CfoKind::SwitchDispatcher.to_string(), "SwitchDispatcher");
    }

    #[test]
    fn cfo_new() {
        let c = ControlFlowObfuscation::new(CfoKind::JunkCode, 0x20, 0x0600_0001, "Foo.Bar");
        assert_eq!(c.method_name, "Foo.Bar");
        assert_eq!(c.il_offset, 0x20);
    }

    // ── RenameObfuscation ─────────────────────────────────────────────────────

    #[test]
    fn rename_looks_obfuscated_short() {
        assert!(RenameObfuscation::looks_obfuscated("a"));
        assert!(RenameObfuscation::looks_obfuscated("ab"));
    }

    #[test]
    fn rename_looks_obfuscated_normal() {
        assert!(!RenameObfuscation::looks_obfuscated("NormalName"));
        assert!(!RenameObfuscation::looks_obfuscated("MyMethod123"));
    }

    #[test]
    fn rename_looks_obfuscated_non_ascii() {
        let name = "m\u{00e9}th"; // accented character
        assert!(RenameObfuscation::looks_obfuscated(name));
    }

    #[test]
    fn rename_looks_obfuscated_repeated() {
        assert!(RenameObfuscation::looks_obfuscated("aaaa"));
    }

    #[test]
    fn rename_new() {
        let r = RenameObfuscation::new("a", 0x0600_0001, "method", "single-char name");
        assert_eq!(r.symbol_kind, "method");
    }

    // ── ProxyMethod ───────────────────────────────────────────────────────────

    #[test]
    fn proxy_method_new() {
        let p = ProxyMethod::new(0x0600_0001, "ProxyFoo", "NS.T");
        assert_eq!(p.proxy_name, "ProxyFoo");
        assert!(!p.is_direct_pass_through);
    }

    // ── CodeInlining ──────────────────────────────────────────────────────────

    #[test]
    fn code_inlining_new() {
        let c = CodeInlining::new(0x0600_0001, 0x0600_0002, "InlinedHelper", 0x10);
        assert_eq!(c.start_offset, 0x10);
        assert_eq!(c.inlined_method_name, "InlinedHelper");
    }

    // ── ObfuscatorSignature ───────────────────────────────────────────────────

    #[test]
    fn signature_display_confuserex() {
        let s = ObfuscatorSignature::new(KnownObfuscator::ConfuserEx, ObfuscationConfidence::High);
        assert_eq!(s.obfuscator.to_string(), "ConfuserEx");
    }

    #[test]
    fn signature_add_indicator() {
        let mut s =
            ObfuscatorSignature::new(KnownObfuscator::Dotfuscator, ObfuscationConfidence::Medium);
        s.add_indicator("DotfuscatorAttribute found");
        assert_eq!(s.indicators.len(), 1);
    }

    // ── ObfuscatedCode ────────────────────────────────────────────────────────

    #[test]
    fn obfuscated_code_empty_not_obfuscated() {
        let oc = ObfuscatedCode::new();
        assert!(!oc.is_obfuscated());
        assert_eq!(oc.total_findings(), 0);
    }

    #[test]
    fn obfuscated_code_with_findings() {
        let mut oc = ObfuscatedCode::new();
        oc.renamed_symbols
            .push(RenameObfuscation::new("a", 1, "type", "short"));
        assert!(oc.is_obfuscated());
        assert_eq!(oc.total_findings(), 1);
    }

    #[test]
    fn obfuscated_code_max_confidence_none() {
        let oc = ObfuscatedCode::new();
        assert!(oc.max_confidence().is_none());
    }

    #[test]
    fn obfuscated_code_max_confidence_high() {
        let mut oc = ObfuscatedCode::new();
        let mut s = StringEncryption::new(0, "T", "M", "Dec");
        s.confidence = ObfuscationConfidence::Low;
        oc.string_encryptions.push(s);
        let sig =
            ObfuscatorSignature::new(KnownObfuscator::ConfuserEx, ObfuscationConfidence::High);
        oc.signatures.push(sig);
        assert_eq!(oc.max_confidence(), Some(ObfuscationConfidence::High));
    }

    // ── MetadataAnalyzer ──────────────────────────────────────────────────────

    #[test]
    fn analyzer_new_defaults() {
        let a = MetadataAnalyzer::new();
        assert!(a.analyze_names);
        assert!(a.detect_proxy_methods);
    }

    #[test]
    fn analyzer_set_and_get_result() {
        let mut a = MetadataAnalyzer::new();
        let mut oc = ObfuscatedCode::new();
        oc.renamed_symbols
            .push(RenameObfuscation::new("x", 1, "method", "short"));
        a.set_result("MyAssembly", oc);
        let r = a.get_result("MyAssembly").unwrap();
        assert!(r.is_obfuscated());
    }

    #[test]
    fn analyzer_obfuscated_assemblies() {
        let mut a = MetadataAnalyzer::new();
        a.set_result("Clean", ObfuscatedCode::new());
        let mut dirty = ObfuscatedCode::new();
        dirty
            .renamed_symbols
            .push(RenameObfuscation::new("a", 1, "type", "short"));
        a.set_result("Dirty", dirty);
        let names = a.obfuscated_assemblies();
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"Dirty"));
    }

    #[test]
    fn analyzer_total_findings() {
        let mut a = MetadataAnalyzer::new();
        let mut oc = ObfuscatedCode::new();
        oc.renamed_symbols
            .push(RenameObfuscation::new("x", 1, "type", "short"));
        oc.proxy_methods.push(ProxyMethod::new(2, "P", "T"));
        a.set_result("A", oc);
        assert_eq!(a.total_findings(), 2);
    }

    #[test]
    fn analyzer_all_signatures() {
        let mut a = MetadataAnalyzer::new();
        let mut oc = ObfuscatedCode::new();
        oc.signatures.push(ObfuscatorSignature::new(
            KnownObfuscator::Eazfuscator,
            ObfuscationConfidence::High,
        ));
        a.set_result("A", oc);
        let sigs = a.all_signatures();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn analyzer_all_encrypted_strings() {
        let mut a = MetadataAnalyzer::new();
        let mut oc = ObfuscatedCode::new();
        oc.string_encryptions
            .push(StringEncryption::new(0, "T", "M", "Dec"));
        a.set_result("A", oc);
        assert_eq!(a.all_encrypted_strings().len(), 1);
    }

    #[test]
    fn analyzer_detect_renamed_types() {
        let a = MetadataAnalyzer::new();
        let types = vec![(1u32, "a"), (2, "NormalName"), (3, "b")];
        let renamed = a.detect_renamed_types(&types);
        assert_eq!(renamed.len(), 2);
    }

    #[test]
    fn analyzer_detect_proxy_method_found() {
        let a = MetadataAnalyzer::new();
        // ldarg.0, ldarg.1, call <token:4 bytes>, ret
        let il = vec![0x02u8, 0x03, 0x28, 0x01, 0x00, 0x00, 0x06, 0x2A];
        let pm = a.detect_proxy_method(0x0600_0001, "Proxy", "T", &il);
        assert!(pm.is_some());
        assert!(pm.unwrap().is_direct_pass_through);
    }

    #[test]
    fn analyzer_detect_proxy_method_not_found_complex() {
        let a = MetadataAnalyzer::new();
        // A method with non-ldarg instructions is not a proxy.
        let il = vec![0x02u8, 0x17, 0x58, 0x28, 0x01, 0x00, 0x00, 0x06, 0x2A]; // add instruction
        let pm = a.detect_proxy_method(1, "Complex", "T", &il);
        assert!(pm.is_none());
    }

    #[test]
    fn analyzer_detect_proxy_empty_il() {
        let a = MetadataAnalyzer::new();
        let pm = a.detect_proxy_method(1, "M", "T", &[]);
        assert!(pm.is_none());
    }

    #[test]
    fn analyzer_detect_signature_confuser() {
        let a = MetadataAnalyzer::new();
        let attrs = vec!["ConfuserExAttribute".to_string()];
        let sig = a.detect_signature_from_attributes(&attrs);
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().obfuscator, KnownObfuscator::ConfuserEx);
    }

    #[test]
    fn analyzer_detect_signature_dotfuscator() {
        let a = MetadataAnalyzer::new();
        let attrs = vec![
            "System.Reflection.Obfuscation".to_string(),
            "DotfuscatorAttribute".to_string(),
        ];
        let sig = a.detect_signature_from_attributes(&attrs);
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().obfuscator, KnownObfuscator::Dotfuscator);
    }

    #[test]
    fn analyzer_detect_signature_none() {
        let a = MetadataAnalyzer::new();
        let attrs = vec!["System.ObsoleteAttribute".to_string()];
        let sig = a.detect_signature_from_attributes(&attrs);
        assert!(sig.is_none());
    }

    #[test]
    fn analyzer_assembly_count() {
        let mut a = MetadataAnalyzer::new();
        a.set_result("A", ObfuscatedCode::new());
        a.set_result("B", ObfuscatedCode::new());
        assert_eq!(a.assembly_count(), 2);
    }

    #[test]
    fn analyzer_get_or_create() {
        let mut a = MetadataAnalyzer::new();
        let oc = a.get_or_create("New");
        oc.renamed_symbols
            .push(RenameObfuscation::new("x", 1, "type", "short"));
        assert_eq!(a.get_result("New").unwrap().total_findings(), 1);
    }

    #[test]
    fn analyzer_all_proxy_methods() {
        let mut a = MetadataAnalyzer::new();
        let mut oc = ObfuscatedCode::new();
        oc.proxy_methods.push(ProxyMethod::new(1, "Proxy1", "T"));
        oc.proxy_methods.push(ProxyMethod::new(2, "Proxy2", "T"));
        a.set_result("A", oc);
        assert_eq!(a.all_proxy_methods().len(), 2);
    }
}
