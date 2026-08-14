//! `die_script_engine` — DIE-style script engine for detection rule execution.
//!
//! Runs structured detection scripts against raw file bytes.  Each script
//! consists of a header (name, kind, version) and one or more condition
//! expressions that are evaluated in order.  A script fires when **all**
//! conditions evaluate to `true`.
//!
//! Key types: [`DieScriptEngine`], [`DieScript`], [`ScriptResult`]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced during script execution.
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("script parse error in '{script}': {reason}")]
    ParseError { script: String, reason: String },
    #[error("execution error in '{script}': {reason}")]
    ExecError { script: String, reason: String },
    #[error("unknown function: {0}")]
    UnknownFunction(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("script not found: {0}")]
    NotFound(String),
}

// ─── ScriptKind ───────────────────────────────────────────────────────────────

/// The category of entity that a script detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScriptKind {
    Compiler,
    Packer,
    Protector,
    Installer,
    Archive,
    Library,
    Tool,
    Custom,
}

impl fmt::Display for ScriptKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ConditionOp ──────────────────────────────────────────────────────────────

/// A single condition operation in a DIE script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOp {
    /// `find_string(s)` — raw string is present anywhere in the file.
    FindString(String),
    /// `find_hex(hex_pattern)` — wildcard hex pattern is present.
    FindHex { pattern: String, offset: Option<usize> },
    /// `section_name(name)` — a PE section with this name exists.
    SectionName(String),
    /// `entry_starts_with(hex)` — entry point bytes match.
    EntryStartsWith(String),
    /// `entropy_range(section_idx, min, max)` — section entropy in range.
    EntropyRange { section: usize, min: f32, max: f32 },
    /// `import_present(dll, func)` — PE import exists.
    ImportPresent { dll: String, func: String },
    /// `is_dotnet()` — file has a CLR header.
    IsDotNet,
    /// `file_size_range(min, max)` — file size within bounds.
    FileSizeRange { min: usize, max: usize },
    /// `not(inner)` — negation of an inner condition.
    Not(Box<ConditionOp>),
    /// `any_of([ops])` — at least one inner condition is true.
    AnyOf(Vec<ConditionOp>),
    /// `all_of([ops])` — all inner conditions are true.
    AllOf(Vec<ConditionOp>),
}

impl ConditionOp {
    /// Evaluate this condition against `data`.
    #[must_use]
    pub fn evaluate(&self, data: &[u8]) -> bool {
        match self {
            Self::FindString(s) => {
                data.windows(s.len()).any(|w| w == s.as_bytes())
            }
            Self::FindHex { pattern, offset } => {
                let start = offset.unwrap_or(0).min(data.len());
                find_hex_pattern(pattern, &data[start..]).is_some()
            }
            Self::SectionName(name) => {
                pe_has_section(data, name)
            }
            Self::EntryStartsWith(hex) => {
                let ep = get_pe_entry_bytes(data);
                match_hex_prefix(&ep, hex)
            }
            Self::EntropyRange { section, min, max } => {
                if let Some(ent) = pe_section_entropy(data, *section) {
                    ent >= *min && ent <= *max
                } else {
                    false
                }
            }
            Self::ImportPresent { dll, func } => {
                pe_import_present(data, dll, func)
            }
            Self::IsDotNet => pe_has_clr_header(data),
            Self::FileSizeRange { min, max } => {
                data.len() >= *min && data.len() <= *max
            }
            Self::Not(inner) => !inner.evaluate(data),
            Self::AnyOf(ops) => ops.iter().any(|op| op.evaluate(data)),
            Self::AllOf(ops) => ops.iter().all(|op| op.evaluate(data)),
        }
    }
}

// ─── DieScript ────────────────────────────────────────────────────────────────

/// A single detection script consisting of a header and condition list.
///
/// A script fires (matches) when **all** of its top-level conditions evaluate
/// to `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieScript {
    /// Unique script name, e.g. `"UPX 3.x"`.
    pub name: String,
    /// The category of entity detected.
    pub kind: ScriptKind,
    /// Version string, e.g. `"3.x"`.
    pub version: Option<String>,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Description shown in the UI.
    pub description: String,
    /// Top-level conditions (all must be true).
    pub conditions: Vec<ConditionOp>,
    /// Metadata tags for script categorisation.
    pub tags: Vec<String>,
}

impl DieScript {
    /// Create a new script with empty conditions.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: ScriptKind) -> Self {
        Self {
            name: name.into(),
            kind,
            version: None,
            confidence: 80,
            description: String::new(),
            conditions: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add a condition to this script.
    #[must_use]
    pub fn with_condition(mut self, cond: ConditionOp) -> Self {
        self.conditions.push(cond);
        self
    }

    /// Set the version string.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the confidence score.
    #[must_use]
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Evaluate whether this script matches `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if self.conditions.is_empty() {
            return false;
        }
        self.conditions.iter().all(|c| c.evaluate(data))
    }
}

// ─── ScriptResult ─────────────────────────────────────────────────────────────

/// The result of running a single script against a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    /// The script's name.
    pub script_name: String,
    /// Whether the script matched.
    pub matched: bool,
    /// The script's kind.
    pub kind: ScriptKind,
    /// Optional version string.
    pub version: Option<String>,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Per-condition match results: `(description, matched)`.
    pub condition_results: Vec<(String, bool)>,
    /// Total evaluation time in microseconds.
    pub eval_us: u64,
}

impl ScriptResult {
    fn from_script(script: &DieScript, matched: bool, cond_results: Vec<(String, bool)>) -> Self {
        Self {
            script_name: script.name.clone(),
            matched,
            kind: script.kind,
            version: script.version.clone(),
            confidence: script.confidence,
            condition_results: cond_results,
            eval_us: 0,
        }
    }
}

impl fmt::Display for ScriptResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}]: matched={} confidence={}",
            self.script_name, self.kind, self.matched, self.confidence
        )
    }
}

// ─── ExecutionContext ─────────────────────────────────────────────────────────

/// Shared context passed to all scripts during a single engine run.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Raw file bytes.
    pub data: Vec<u8>,
    /// Custom key-value context (e.g. file path, pre-computed values).
    pub vars: HashMap<String, String>,
}

impl ExecutionContext {
    /// Create a context from raw bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            vars: HashMap::new(),
        }
    }

    /// Add a custom variable.
    pub fn set_var(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.vars.insert(key.into(), val.into());
    }
}

// ─── DieScriptEngine ──────────────────────────────────────────────────────────

/// The DIE script engine: holds a registry of scripts and evaluates them.
pub struct DieScriptEngine {
    scripts: Vec<DieScript>,
}

impl DieScriptEngine {
    /// Create a new, empty engine.
    #[must_use]
    pub fn new() -> Self {
        Self { scripts: Vec::new() }
    }

    /// Create an engine pre-loaded with a standard set of detection scripts.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut engine = Self::new();
        engine.load_defaults();
        engine
    }

    /// Load the built-in default detection scripts.
    pub fn load_defaults(&mut self) {
        // ── Packers ──────────────────────────────────────────────────────────
        self.register(
            DieScript::new("UPX", ScriptKind::Packer)
                .with_version("3.x")
                .with_confidence(97)
                .with_description("Ultimate Packer for eXecutables")
                .with_condition(ConditionOp::SectionName("UPX0".to_string()))
                .with_condition(ConditionOp::SectionName("UPX1".to_string())),
        );
        self.register(
            DieScript::new("MPRESS", ScriptKind::Packer)
                .with_version("2.x")
                .with_confidence(92)
                .with_condition(ConditionOp::SectionName(".MPRESS1".to_string())),
        );
        self.register(
            DieScript::new("ASPack", ScriptKind::Packer)
                .with_version("2.x")
                .with_confidence(91)
                .with_condition(ConditionOp::SectionName(".aspack".to_string())),
        );
        self.register(
            DieScript::new("PECompact", ScriptKind::Packer)
                .with_version("2.x")
                .with_confidence(90)
                .with_condition(ConditionOp::FindString("PECompact2".to_string())),
        );
        self.register(
            DieScript::new("NsPack", ScriptKind::Packer)
                .with_version("3.x")
                .with_confidence(88)
                .with_condition(ConditionOp::SectionName(".nsp0".to_string())),
        );
        self.register(
            DieScript::new("PyInstaller", ScriptKind::Tool)
                .with_version("6.x")
                .with_confidence(95)
                .with_condition(ConditionOp::FindString("MEI\x0C\x0B\x0A\x0B\x0E".to_string())),
        );

        // ── Protectors ────────────────────────────────────────────────────────
        self.register(
            DieScript::new("Themida", ScriptKind::Protector)
                .with_version("3.x")
                .with_confidence(93)
                .with_condition(ConditionOp::SectionName(".themida".to_string())),
        );
        self.register(
            DieScript::new("VMProtect", ScriptKind::Protector)
                .with_version("3.x")
                .with_confidence(93)
                .with_condition(ConditionOp::AnyOf(vec![
                    ConditionOp::SectionName(".vmp0".to_string()),
                    ConditionOp::SectionName(".vmp1".to_string()),
                ])),
        );
        self.register(
            DieScript::new("Obsidium", ScriptKind::Protector)
                .with_version("1.x")
                .with_confidence(88)
                .with_condition(ConditionOp::FindString("Obsidium".to_string())),
        );

        // ── Compilers ─────────────────────────────────────────────────────────
        self.register(
            DieScript::new("GCC/MinGW", ScriptKind::Compiler)
                .with_version("4.x+")
                .with_confidence(82)
                .with_condition(ConditionOp::FindString("MinGW".to_string())),
        );
        self.register(
            DieScript::new("Clang", ScriptKind::Compiler)
                .with_version("10+")
                .with_confidence(80)
                .with_condition(ConditionOp::FindString("clang".to_string())),
        );
        self.register(
            DieScript::new("Delphi", ScriptKind::Compiler)
                .with_version("7+")
                .with_confidence(87)
                .with_condition(ConditionOp::FindString("Borland".to_string())),
        );
        self.register(
            DieScript::new("Visual Basic 6", ScriptKind::Compiler)
                .with_version("6.0")
                .with_confidence(90)
                .with_condition(ConditionOp::FindString("VB5!".to_string())),
        );
        self.register(
            DieScript::new("Rust", ScriptKind::Compiler)
                .with_version("1.x")
                .with_confidence(85)
                .with_condition(ConditionOp::FindString("rustc".to_string())),
        );
        self.register(
            DieScript::new("AutoIt", ScriptKind::Tool)
                .with_version("3.x")
                .with_confidence(93)
                .with_condition(ConditionOp::FindString("AU3!EA".to_string())),
        );

        // ── Installers ────────────────────────────────────────────────────────
        self.register(
            DieScript::new("NSIS", ScriptKind::Installer)
                .with_version("3.x")
                .with_confidence(87)
                .with_condition(ConditionOp::FindString("Nullsoft".to_string())),
        );
        self.register(
            DieScript::new("Inno Setup", ScriptKind::Installer)
                .with_version("6.x")
                .with_confidence(90)
                .with_condition(ConditionOp::FindString("Inno Setup".to_string())),
        );
    }

    /// Register a new script.
    pub fn register(&mut self, script: DieScript) {
        self.scripts.push(script);
    }

    /// Remove all scripts whose name equals `name`.
    pub fn remove(&mut self, name: &str) {
        self.scripts.retain(|s| s.name != name);
    }

    /// Look up a script by name.
    #[must_use]
    pub fn get_script(&self, name: &str) -> Option<&DieScript> {
        self.scripts.iter().find(|s| s.name == name)
    }

    /// Return the total number of registered scripts.
    #[must_use]
    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }

    /// Execute all scripts against `ctx` and return every matching result.
    #[must_use]
    pub fn execute_all(&self, ctx: &ExecutionContext) -> Vec<ScriptResult> {
        self.scripts
            .iter()
            .map(|s| execute_script(s, ctx))
            .filter(|r| r.matched)
            .collect()
    }

    /// Execute a single named script and return its result.
    ///
    /// # Errors
    /// Returns [`ScriptError::NotFound`] if no script with the given name exists.
    pub fn execute_named(
        &self,
        name: &str,
        ctx: &ExecutionContext,
    ) -> Result<ScriptResult, ScriptError> {
        let script = self
            .scripts
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ScriptError::NotFound(name.to_string()))?;
        Ok(execute_script(script, ctx))
    }

    /// Return all scripts of the given kind.
    #[must_use]
    pub fn scripts_of_kind(&self, kind: ScriptKind) -> Vec<&DieScript> {
        self.scripts.iter().filter(|s| s.kind == kind).collect()
    }

    /// Return a summary: kind → count of registered scripts.
    #[must_use]
    pub fn kind_summary(&self) -> HashMap<ScriptKind, usize> {
        let mut map: HashMap<ScriptKind, usize> = HashMap::new();
        for s in &self.scripts {
            *map.entry(s.kind).or_insert(0) += 1;
        }
        map
    }
}

impl Default for DieScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute a single script against a context and return the result.
#[must_use]
pub fn execute_script(script: &DieScript, ctx: &ExecutionContext) -> ScriptResult {
    let data = &ctx.data;
    let mut cond_results = Vec::with_capacity(script.conditions.len());
    let mut all_match = !script.conditions.is_empty();

    for cond in &script.conditions {
        let result = cond.evaluate(data);
        cond_results.push((format!("{cond:?}"), result));
        if !result {
            all_match = false;
        }
    }

    if script.conditions.is_empty() {
        all_match = false;
    }

    ScriptResult::from_script(script, all_match, cond_results)
}

// ─── PE helpers (lightweight duplicates for standalone use) ──────────────────

fn pe_has_section(data: &[u8], name: &str) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    if &data[0..2] != b"MZ" {
        return false;
    }
    let pe_off = match u32::from_le_bytes(data[0x3c..0x40].try_into().ok().unwrap_or([0u8; 4])) {
        0 => return false,
        v => v as usize,
    };
    if pe_off + 6 > data.len() {
        return false;
    }
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;
    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 8 > data.len() {
            break;
        }
        let nb = &data[s..s + 8];
        let end = nb.iter().position(|&b| b == 0).unwrap_or(8);
        if let Ok(sec_name) = std::str::from_utf8(&nb[..end]) {
            if sec_name == name {
                return true;
            }
        }
    }
    false
}

fn get_pe_entry_bytes(data: &[u8]) -> Vec<u8> {
    crate::get_entry_point_bytes(data)
}

fn match_hex_prefix(ep: &[u8], hex: &str) -> bool {
    let tokens: Vec<Option<u8>> = hex
        .split_whitespace()
        .map(|t| {
            if t == "??" { None } else { u8::from_str_radix(t, 16).ok() }
        })
        .collect();
    if tokens.len() > ep.len() {
        return false;
    }
    tokens.iter().enumerate().all(|(i, mb)| mb.map_or(true, |b| ep[i] == b))
}

fn pe_section_entropy(data: &[u8], section_idx: usize) -> Option<f32> {
    let sections = crate::read_pe_sections(data);
    sections.get(section_idx).map(|(_, e)| *e)
}

fn pe_import_present(data: &[u8], dll: &str, func: &str) -> bool {
    crate::check_imports(data, dll, func)
}

fn pe_has_clr_header(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    if &data[0..2] != b"MZ" {
        return false;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0u8; 4])) as usize;
    if pe_off + 4 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let clr_off = if magic == 0x020b {
        opt_off + 0x70 + 14 * 8
    } else {
        opt_off + 0x60 + 14 * 8
    };
    if clr_off + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes(data[clr_off..clr_off + 4].try_into().unwrap_or([0u8; 4]));
    let size = u32::from_le_bytes(data[clr_off + 4..clr_off + 8].try_into().unwrap_or([0u8; 4]));
    rva != 0 && size != 0
}

fn find_hex_pattern(pattern: &str, data: &[u8]) -> Option<usize> {
    crate::find_bytes(data, pattern)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn data_with(strings: &[&str]) -> Vec<u8> {
        let mut v = b"MZ".to_vec();
        v.resize(0x100, 0);
        for s in strings {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v
    }

    #[test]
    fn engine_default_has_scripts() {
        let engine = DieScriptEngine::with_defaults();
        assert!(engine.script_count() > 5);
    }

    #[test]
    fn engine_register_custom() {
        let mut engine = DieScriptEngine::new();
        engine.register(
            DieScript::new("MyPacker", ScriptKind::Packer)
                .with_condition(ConditionOp::FindString("MYPK".to_string())),
        );
        assert_eq!(engine.script_count(), 1);
    }

    #[test]
    fn engine_execute_all_matches() {
        let mut engine = DieScriptEngine::new();
        engine.register(
            DieScript::new("UPX_test", ScriptKind::Packer)
                .with_condition(ConditionOp::FindString("UPX0".to_string())),
        );
        let ctx = ExecutionContext::new(data_with(&["UPX0"]));
        let results = engine.execute_all(&ctx);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].script_name, "UPX_test");
    }

    #[test]
    fn engine_execute_all_no_match() {
        let engine = DieScriptEngine::with_defaults();
        let ctx = ExecutionContext::new(vec![0u8; 256]);
        let results = engine.execute_all(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn engine_execute_named_found() {
        let mut engine = DieScriptEngine::new();
        engine.register(
            DieScript::new("TestScript", ScriptKind::Tool)
                .with_condition(ConditionOp::FindString("hello".to_string())),
        );
        let ctx = ExecutionContext::new(b"hello world".to_vec());
        let result = engine.execute_named("TestScript", &ctx).unwrap();
        assert!(result.matched);
    }

    #[test]
    fn engine_execute_named_not_found() {
        let engine = DieScriptEngine::new();
        let ctx = ExecutionContext::new(vec![]);
        let err = engine.execute_named("NoSuchScript", &ctx).unwrap_err();
        assert!(matches!(err, ScriptError::NotFound(_)));
    }

    #[test]
    fn condition_find_string_true() {
        let cond = ConditionOp::FindString("rustc".to_string());
        assert!(cond.evaluate(b"contains rustc version"));
    }

    #[test]
    fn condition_find_string_false() {
        let cond = ConditionOp::FindString("rustc".to_string());
        assert!(!cond.evaluate(b"no match here"));
    }

    #[test]
    fn condition_file_size_range() {
        let cond = ConditionOp::FileSizeRange { min: 10, max: 100 };
        assert!(cond.evaluate(&[0u8; 50]));
        assert!(!cond.evaluate(&[0u8; 5]));
        assert!(!cond.evaluate(&[0u8; 200]));
    }

    #[test]
    fn condition_not_inverts() {
        let inner = Box::new(ConditionOp::FindString("absent".to_string()));
        let cond = ConditionOp::Not(inner);
        assert!(cond.evaluate(b"no such thing here"));
        assert!(!cond.evaluate(b"absent from nowhere"));
    }

    #[test]
    fn condition_any_of() {
        let cond = ConditionOp::AnyOf(vec![
            ConditionOp::FindString("alpha".to_string()),
            ConditionOp::FindString("beta".to_string()),
        ]);
        assert!(cond.evaluate(b"contains beta string"));
        assert!(!cond.evaluate(b"neither here"));
    }

    #[test]
    fn condition_all_of() {
        let cond = ConditionOp::AllOf(vec![
            ConditionOp::FindString("a".to_string()),
            ConditionOp::FindString("b".to_string()),
        ]);
        assert!(cond.evaluate(b"a and b here"));
        assert!(!cond.evaluate(b"only a here"));
    }

    #[test]
    fn script_no_conditions_never_matches() {
        let script = DieScript::new("Empty", ScriptKind::Tool);
        let ctx = ExecutionContext::new(vec![1, 2, 3]);
        let result = execute_script(&script, &ctx);
        assert!(!result.matched);
    }

    #[test]
    fn script_result_display() {
        let r = ScriptResult {
            script_name: "UPX".to_string(),
            matched: true,
            kind: ScriptKind::Packer,
            version: Some("3.x".to_string()),
            confidence: 97,
            condition_results: vec![],
            eval_us: 0,
        };
        let s = r.to_string();
        assert!(s.contains("UPX"));
        assert!(s.contains("97"));
    }

    #[test]
    fn script_kind_summary() {
        let engine = DieScriptEngine::with_defaults();
        let summary = engine.kind_summary();
        assert!(summary.contains_key(&ScriptKind::Packer));
        assert!(summary.contains_key(&ScriptKind::Protector));
    }

    #[test]
    fn engine_remove_script() {
        let mut engine = DieScriptEngine::with_defaults();
        let before = engine.script_count();
        engine.remove("UPX");
        assert!(engine.script_count() < before);
    }

    #[test]
    fn scripts_of_kind_returns_correct() {
        let engine = DieScriptEngine::with_defaults();
        let packers = engine.scripts_of_kind(ScriptKind::Packer);
        assert!(!packers.is_empty());
        for p in &packers {
            assert_eq!(p.kind, ScriptKind::Packer);
        }
    }
}
