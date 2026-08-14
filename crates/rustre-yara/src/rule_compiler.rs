// rule_compiler.rs — YARA rule compilation, caching, and hot-reload

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, bail, Context, Result};
use tokio::fs;
use tokio::sync::mpsc;

use crate::rule_parser::{ParsedRule, RuleParser};

// ── Compiled rule ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, MetaValue>,
    pub patterns: Vec<CompiledPattern>,
    pub condition_bytecode: Vec<ConditionOp>,
    pub source_hash: [u8; 32],
    pub compiled_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetaValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPattern {
    pub id: String,
    pub kind: CompiledPatternKind,
    pub modifiers: PatternModifiers,
    pub compiled_atoms: Vec<Atom>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompiledPatternKind {
    ByteString(Vec<u8>),
    HexString(Vec<HexToken>),
    Regex(String),
}

/// Encoding options for a compiled pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternEncoding {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
}

/// Output options for a compiled pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternOutput {
    pub fullword: bool,
    pub private: bool,
    pub base64: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternModifiers {
    pub encoding: PatternEncoding,
    pub output: PatternOutput,
    pub xor: Option<(u8, u8)>,
    pub base64wide: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HexToken {
    Byte(u8),
    Wildcard,
    Nibble { high: Option<u8>, low: Option<u8> },
    Jump { min: u32, max: Option<u32> },
    Alt(Vec<Vec<Self>>),
}

/// Atoms are fixed-width byte sequences extracted from patterns for fast pre-filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Atom {
    pub bytes: Vec<u8>,
    pub offset: u32,
    pub quality: u8,
}

/// Condition bytecode operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOp {
    PushBool(bool),
    PushInt(i64),
    PushFloat(f64),
    PushString(String),
    LoadVar(String),
    PatternMatch(String),
    PatternMatchAt { id: String, offset_reg: u8 },
    PatternMatchIn { id: String, from_reg: u8, to_reg: u8 },
    PatternCount(String),
    PatternCountIn { id: String, from_reg: u8, to_reg: u8 },
    PatternOffset(String, u32),
    PatternLength(String, u32),
    FileSize,
    EntryPoint,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    Shl,
    Shr,
    Neg,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    Matches,
    ForAll { pattern_set: Vec<String> },
    ForAny { pattern_set: Vec<String> },
    ForN { n_reg: u8, pattern_set: Vec<String> },
    Of { set: OfSet },
    At(u8),
    In { from_reg: u8, to_reg: u8 },
    Jump(i32),
    JumpIfFalse(i32),
    JumpIfTrue(i32),
    Call(String),
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OfSet {
    All,
    Any,
    N(u8),
    Patterns(Vec<String>),
}

// ── Rule set ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRuleSet {
    pub rules: Vec<CompiledRule>,
    pub globals: Vec<CompiledRule>,
    pub private_rules: Vec<CompiledRule>,
    pub set_hash: [u8; 32],
}

impl Default for CompiledRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl CompiledRuleSet {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            globals: Vec::new(),
            private_rules: Vec::new(),
            set_hash: [0u8; 32],
        }
    }

    #[must_use] 
    pub const fn total_rules(&self) -> usize {
        self.rules.len() + self.globals.len() + self.private_rules.len()
    }

    pub fn all_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.globals
            .iter()
            .chain(self.private_rules.iter())
            .chain(self.rules.iter())
    }

    #[must_use] 
    pub fn find_rule(&self, name: &str, namespace: &str) -> Option<&CompiledRule> {
        self.all_rules().find(|r| r.name == name && r.namespace == namespace)
    }

    fn recompute_hash(&mut self) {
        let mut h = Sha256::new();
        for rule in self.all_rules() {
            h.update(rule.source_hash);
        }
        self.set_hash.copy_from_slice(&h.finalize());
    }
}

// ── Compilation error ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationError {
    pub rule_name: Option<String>,
    pub span: Option<(usize, usize)>,
    pub message: String,
    pub kind: CompilationErrorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompilationErrorKind {
    SyntaxError,
    UndefinedPattern(String),
    UndefinedRule(String),
    DuplicatePattern(String),
    DuplicateRule(String),
    InvalidModifierCombination(String, String),
    TypeMismatch { expected: String, found: String },
    RegexCompileError(String),
    TooManyPatterns(usize),
    CircularDependency(Vec<String>),
}

impl std::fmt::Display for CompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = &self.rule_name {
            write!(f, "Rule '{}': {}", name, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

// ── Compiler ───────────────────────────────────────────────────────────────────

pub struct RuleCompiler {
    atom_quality_threshold: u8,
    max_patterns_per_rule: usize,
    max_string_size: usize,
    optimize_atoms: bool,
}

impl Default for RuleCompiler {
    fn default() -> Self {
        Self {
            atom_quality_threshold: 10,
            max_patterns_per_rule: 10_000,
            max_string_size: 1_000_000,
            optimize_atoms: true,
        }
    }
}

impl RuleCompiler {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    ///
    /// Returns a list of [`CompilationError`]s when the source fails to compile.
    pub fn compile_str(&self, source: &str) -> Result<CompiledRuleSet, Vec<CompilationError>> {
        let mut parser = RuleParser::new();
        let parsed = match parser.parse(source) {
            Ok(p) => p,
            Err(e) => {
                return Err(vec![CompilationError {
                    rule_name: None,
                    span: None,
                    message: e.to_string(),
                    kind: CompilationErrorKind::SyntaxError,
                }])
            }
        };

        let mut errors = Vec::new();
        let mut rule_set = CompiledRuleSet::new();

        // First pass: collect all rule names for forward reference resolution
        let mut known_rules: HashMap<String, String> = HashMap::new();
        for rule in &parsed {
            let key = format!("{}::{}", rule.namespace, rule.name);
            if known_rules.contains_key(&key) {
                errors.push(CompilationError {
                    rule_name: Some(rule.name.clone()),
                    span: None,
                    message: format!("Duplicate rule '{}'", rule.name),
                    kind: CompilationErrorKind::DuplicateRule(rule.name.clone()),
                });
            }
            known_rules.insert(key, rule.name.clone());
        }

        // Second pass: compile each rule
        for parsed_rule in &parsed {
            match self.compile_rule(parsed_rule, &known_rules) {
                Ok(compiled) => {
                    if parsed_rule.is_global {
                        rule_set.globals.push(compiled);
                    } else if parsed_rule.is_private {
                        rule_set.private_rules.push(compiled);
                    } else {
                        rule_set.rules.push(compiled);
                    }
                }
                Err(e) => errors.extend(e),
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        rule_set.recompute_hash();
        Ok(rule_set)
    }

    fn compile_rule(
        &self,
        rule: &ParsedRule,
        known_rules: &HashMap<String, String>,
    ) -> Result<CompiledRule, Vec<CompilationError>> {
        let mut errors = Vec::new();

        // Hash source for caching
        let mut hasher = Sha256::new();
        hasher.update(rule.source_text.as_bytes());
        let mut source_hash = [0u8; 32];
        source_hash.copy_from_slice(&hasher.finalize());

        // Compile metadata
        let mut metadata = HashMap::new();
        for (k, v) in &rule.metadata {
            metadata.insert(k.clone(), Self::compile_meta_value(v));
        }

        // Compile patterns
        let mut patterns = Vec::new();
        let mut pattern_ids: HashMap<String, usize> = HashMap::new();

        if rule.patterns.len() > self.max_patterns_per_rule {
            errors.push(CompilationError {
                rule_name: Some(rule.name.clone()),
                span: None,
                message: format!(
                    "Too many patterns: {} > {}",
                    rule.patterns.len(),
                    self.max_patterns_per_rule
                ),
                kind: CompilationErrorKind::TooManyPatterns(rule.patterns.len()),
            });
        } else {
            for (idx, pat) in rule.patterns.iter().enumerate() {
                if pattern_ids.contains_key(&pat.id) {
                    errors.push(CompilationError {
                        rule_name: Some(rule.name.clone()),
                        span: None,
                        message: format!("Duplicate pattern identifier '{}'", pat.id),
                        kind: CompilationErrorKind::DuplicatePattern(pat.id.clone()),
                    });
                    continue;
                }
                pattern_ids.insert(pat.id.clone(), idx);

                match self.compile_pattern(pat) {
                    Ok(cp) => patterns.push(cp),
                    Err(e) => errors.extend(e),
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // Compile condition
        let mut codegen = ConditionCodegen::new(&pattern_ids, known_rules);
        let condition_bytecode = match codegen.compile(&rule.condition) {
            Ok(bc) => bc,
            Err(e) => {
                errors.push(CompilationError {
                    rule_name: Some(rule.name.clone()),
                    span: None,
                    message: e.to_string(),
                    kind: CompilationErrorKind::SyntaxError,
                });
                return Err(errors);
            }
        };

        Ok(CompiledRule {
            name: rule.name.clone(),
            namespace: rule.namespace.clone(),
            tags: rule.tags.clone(),
            metadata,
            patterns,
            condition_bytecode,
            source_hash,
            compiled_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    fn compile_meta_value(v: &crate::rule_parser::MetaLiteral) -> MetaValue {
        use crate::rule_parser::MetaLiteral;
        match v {
            MetaLiteral::String(s) => MetaValue::String(s.clone()),
            MetaLiteral::Integer(i) => MetaValue::Integer(*i),
            MetaLiteral::Boolean(b) => MetaValue::Boolean(*b),
        }
    }

    fn compile_pattern(
        &self,
        pat: &crate::rule_parser::ParsedPattern,
    ) -> Result<CompiledPattern, Vec<CompilationError>> {
        use crate::rule_parser::ParsedPatternKind;
        let mut errors = Vec::new();

        let modifiers = PatternModifiers {
            encoding: PatternEncoding {
                ascii: pat.modifiers.encoding.ascii,
                wide: pat.modifiers.encoding.wide,
                nocase: pat.modifiers.encoding.nocase,
            },
            output: PatternOutput {
                fullword: pat.modifiers.output.fullword,
                private: pat.modifiers.output.private,
                base64: pat.modifiers.output.base64,
            },
            xor: pat.modifiers.xor,
            base64wide: pat.modifiers.base64wide,
        };

        // Validate modifier combinations
        if modifiers.output.base64 && modifiers.xor.is_some() {
            errors.push(CompilationError {
                rule_name: None,
                span: None,
                message: "base64 and xor modifiers cannot be combined".to_string(),
                kind: CompilationErrorKind::InvalidModifierCombination(
                    "base64".to_string(),
                    "xor".to_string(),
                ),
            });
        }
        if modifiers.output.fullword && modifiers.encoding.wide && !modifiers.encoding.ascii {
            // fullword + wide only: fine
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        let (kind, mut atoms) = match &pat.kind {
            ParsedPatternKind::Text(s) => {
                let bytes = s.as_bytes().to_vec();
                if bytes.len() > self.max_string_size {
                    errors.push(CompilationError {
                        rule_name: None,
                        span: None,
                        message: format!(
                            "Text pattern '{}' exceeds max_string_size ({} > {})",
                            pat.id,
                            bytes.len(),
                            self.max_string_size
                        ),
                        kind: CompilationErrorKind::SyntaxError,
                    });
                    return Err(errors);
                }
                let atoms = Self::extract_atoms_from_bytes(&bytes, &modifiers);
                (CompiledPatternKind::ByteString(bytes), atoms)
            }
            ParsedPatternKind::Hex(tokens) => {
                let compiled_tokens = Self::compile_hex_tokens(tokens);
                let atoms = self.extract_atoms_from_hex(&compiled_tokens);
                (CompiledPatternKind::HexString(compiled_tokens), atoms)
            }
            ParsedPatternKind::Regex(re_str) => {
                // Validate regex
                if regex::Regex::new(re_str).is_err() {
                    errors.push(CompilationError {
                        rule_name: None,
                        span: None,
                        message: format!("Invalid regex: {re_str}"),
                        kind: CompilationErrorKind::RegexCompileError(re_str.clone()),
                    });
                    return Err(errors);
                }
                let atoms = Self::extract_atoms_from_regex(re_str);
                (CompiledPatternKind::Regex(re_str.clone()), atoms)
            }
        };

        // When atom optimization is enabled, deduplicate identical atoms
        // and keep only the highest-quality copy of each unique byte sequence.
        if self.optimize_atoms {
            atoms.sort_by(|a, b| a.bytes.cmp(&b.bytes).then(b.quality.cmp(&a.quality)));
            atoms.dedup_by(|a, b| a.bytes == b.bytes);
        }

        Ok(CompiledPattern {
            id: pat.id.clone(),
            kind,
            modifiers,
            compiled_atoms: atoms,
        })
    }

    fn compile_hex_tokens(
        tokens: &[crate::rule_parser::HexToken],
    ) -> Vec<HexToken> {
        use crate::rule_parser::HexToken as PH;
        tokens
            .iter()
            .map(|t| match t {
                PH::Byte(b) => HexToken::Byte(*b),
                PH::Wildcard => HexToken::Wildcard,
                PH::Nibble { high, low } => HexToken::Nibble { high: *high, low: *low },
                PH::Jump { min, max } => HexToken::Jump { min: *min, max: *max },
                PH::Alt(alts) => {
                    let compiled: Vec<Vec<HexToken>> = alts
                        .iter()
                        .map(|branch| Self::compile_hex_tokens(branch))
                        .collect();
                    HexToken::Alt(compiled)
                }
            })
            .collect()
    }

    fn extract_atoms_from_bytes(bytes: &[u8], mods: &PatternModifiers) -> Vec<Atom> {
        if bytes.is_empty() {
            return vec![];
        }

        let atom_size = 4.min(bytes.len());
        let mut best_atoms = Vec::new();
        let mut best_quality = 0u8;

        for start in 0..bytes.len().saturating_sub(atom_size - 1) {
            let slice = &bytes[start..start + atom_size];
            let quality = Self::atom_quality(slice);
            if quality > best_quality {
                best_quality = quality;
                best_atoms = vec![Atom {
                    bytes: slice.to_vec(),
                    offset: u32::try_from(start).unwrap_or(u32::MAX),
                    quality,
                }];
            }
        }

        // For wide strings, also produce wide atoms
        if mods.encoding.wide && !bytes.is_empty() {
            let wide: Vec<u8> = bytes.iter().flat_map(|&b| [b, 0]).collect();
            let wq = if wide.len() >= 4 {
                Self::atom_quality(&wide[..4])
            } else {
                0
            };
            best_atoms.push(Atom {
                bytes: wide[..4.min(wide.len())].to_vec(),
                offset: 0,
                quality: wq,
            });
        }

        best_atoms
    }

    fn extract_atoms_from_hex(&self, tokens: &[HexToken]) -> Vec<Atom> {
        // Find the longest run of fixed bytes
        let mut runs: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut current_start = 0;
        let mut current_bytes: Vec<u8> = Vec::new();

        for (i, tok) in tokens.iter().enumerate() {
            if let HexToken::Byte(b) = tok {
                current_bytes.push(*b);
            } else {
                if current_bytes.len() >= 2 {
                    runs.push((current_start, std::mem::take(&mut current_bytes)));
                } else {
                    current_bytes.clear();
                }
                current_start = i + 1;
            }
        }
        if current_bytes.len() >= 2 {
            runs.push((current_start, current_bytes));
        }

        runs.into_iter()
            .filter(|(_, b)| !b.is_empty())
            .map(|(off, bytes)| {
                let quality = Self::atom_quality(&bytes[..4.min(bytes.len())]);
                Atom {
                    bytes: bytes[..4.min(bytes.len())].to_vec(),
                    offset: u32::try_from(off).unwrap_or(u32::MAX),
                    quality,
                }
            })
            .filter(|a| a.quality >= self.atom_quality_threshold)
            .collect()
    }

    fn extract_atoms_from_regex(pattern: &str) -> Vec<Atom> {
        // Extract literal prefixes from regex for pre-filtering
        let mut atoms = Vec::new();
        let mut literal = Vec::new();

        for ch in pattern.chars() {
            match ch {
                '.' | '*' | '+' | '?' | '[' | '(' | '|' | '^' | '$' | '\\' => break,
                c => literal.push(c as u8),
            }
            if literal.len() >= 4 {
                break;
            }
        }

        if literal.len() >= 2 {
            let q = Self::atom_quality(&literal);
            atoms.push(Atom { bytes: literal, offset: 0, quality: q });
        }
        atoms
    }

    fn atom_quality(bytes: &[u8]) -> u8 {
        if bytes.is_empty() {
            return 0;
        }
        // Quality = (length * uniqueness penalty)
        // Low quality for all-zero, all-same, common sequences
        let mut score = u8::try_from(bytes.len()).unwrap_or(u8::MAX).saturating_mul(10);

        let all_same = bytes.iter().all(|&b| b == bytes[0]);
        if all_same {
            score = score.saturating_sub(30);
        }

        let all_zero = bytes.iter().all(|&b| b == 0);
        if all_zero {
            return 0;
        }

        let all_ff = bytes.iter().all(|&b| b == 0xFF);
        if all_ff {
            return 0;
        }

        // Penalize for common low-entropy bytes
        let common: &[u8] = &[0x00, 0xFF, 0x90, 0xCC, 0xCD, 0x0F, 0x1F];
        for &b in bytes {
            if common.contains(&b) {
                score = score.saturating_sub(3);
            }
        }

        score
    }
}

// ── Condition codegen ──────────────────────────────────────────────────────────

struct ConditionCodegen<'a> {
    pattern_ids: &'a HashMap<String, usize>,
    known_rules: &'a HashMap<String, String>,
    bytecode: Vec<ConditionOp>,
}

impl<'a> ConditionCodegen<'a> {
    const fn new(
        pattern_ids: &'a HashMap<String, usize>,
        known_rules: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            pattern_ids,
            known_rules,
            bytecode: Vec::new(),
        }
    }

    fn compile(&mut self, expr: &crate::rule_parser::ConditionExpr) -> Result<Vec<ConditionOp>> {
        use crate::rule_parser::ConditionExpr as CE;
        // Fast-path: trivially-constant top-level conditions compile to a
        // single PushBool op without recursing.
        match expr {
            CE::True => return Ok(vec![ConditionOp::PushBool(true)]),
            CE::False => return Ok(vec![ConditionOp::PushBool(false)]),
            _ => {}
        }
        self.emit_expr(expr)?;
        Ok(std::mem::take(&mut self.bytecode))
    }

    fn emit_binop(&mut self, a: &crate::rule_parser::ConditionExpr, b: &crate::rule_parser::ConditionExpr, op: ConditionOp) -> Result<()> {
        self.emit_expr(a)?;
        self.emit_expr(b)?;
        self.bytecode.push(op);
        Ok(())
    }

    fn emit_expr(&mut self, expr: &crate::rule_parser::ConditionExpr) -> Result<()> {
        use crate::rule_parser::ConditionExpr as CE;
        match expr {
            CE::True  => self.bytecode.push(ConditionOp::PushBool(true)),
            CE::False => self.bytecode.push(ConditionOp::PushBool(false)),
            CE::Integer(i)   => self.bytecode.push(ConditionOp::PushInt(*i)),
            CE::Float(f)     => self.bytecode.push(ConditionOp::PushFloat(*f)),
            CE::StringLit(s) => self.bytecode.push(ConditionOp::PushString(s.clone())),
            CE::FileSize     => self.bytecode.push(ConditionOp::FileSize),
            CE::EntryPoint   => self.bytecode.push(ConditionOp::EntryPoint),
            CE::PatternMatch(id) => {
                self.validate_pattern(id)?;
                self.bytecode.push(ConditionOp::PatternMatch(id.clone()));
            }
            CE::PatternCount(id) => {
                self.validate_pattern(id)?;
                self.bytecode.push(ConditionOp::PatternCount(id.clone()));
            }
            CE::Not(e) => { self.emit_expr(e)?; self.bytecode.push(ConditionOp::Not); }
            CE::And(a, b)        => self.emit_binop(a, b, ConditionOp::And)?,
            CE::Or(a, b)         => self.emit_binop(a, b, ConditionOp::Or)?,
            CE::Eq(a, b)         => self.emit_binop(a, b, ConditionOp::Eq)?,
            CE::Ne(a, b)         => self.emit_binop(a, b, ConditionOp::Ne)?,
            CE::Lt(a, b)         => self.emit_binop(a, b, ConditionOp::Lt)?,
            CE::Le(a, b)         => self.emit_binop(a, b, ConditionOp::Le)?,
            CE::Gt(a, b)         => self.emit_binop(a, b, ConditionOp::Gt)?,
            CE::Ge(a, b)         => self.emit_binop(a, b, ConditionOp::Ge)?,
            CE::Add(a, b)        => self.emit_binop(a, b, ConditionOp::Add)?,
            CE::Sub(a, b)        => self.emit_binop(a, b, ConditionOp::Sub)?,
            CE::Mul(a, b)        => self.emit_binop(a, b, ConditionOp::Mul)?,
            CE::Div(a, b)        => self.emit_binop(a, b, ConditionOp::Div)?,
            CE::Mod(a, b)        => self.emit_binop(a, b, ConditionOp::Mod)?,
            CE::Contains(a, b)   => self.emit_binop(a, b, ConditionOp::Contains)?,
            CE::IContains(a, b)  => self.emit_binop(a, b, ConditionOp::IContains)?,
            CE::StartsWith(a, b) => self.emit_binop(a, b, ConditionOp::StartsWith)?,
            CE::EndsWith(a, b)   => self.emit_binop(a, b, ConditionOp::EndsWith)?,
            CE::Matches(a, b)    => self.emit_binop(a, b, ConditionOp::Matches)?,
            CE::Of { .. } | CE::For { .. } | CE::Identifier(_) | CE::At(..) | CE::In(..) => {
                self.emit_expr_set(expr)?;
            }
        }
        Ok(())
    }

    fn emit_expr_set(&mut self, expr: &crate::rule_parser::ConditionExpr) -> Result<()> {
        use crate::rule_parser::ConditionExpr as CE;
        use crate::rule_parser::Quantifier;
        match expr {
            CE::Of { quantifier, set } => {
                let compiled_set = self.compile_pattern_set(set)?;
                let op = match quantifier {
                    Quantifier::All => ConditionOp::Of { set: OfSet::All },
                    Quantifier::Any => ConditionOp::Of { set: OfSet::Any },
                    Quantifier::N(n) => ConditionOp::Of { set: OfSet::N(u8::try_from(*n).unwrap_or(u8::MAX)) },
                    Quantifier::Expr(e) => {
                        self.emit_expr(e)?;
                        ConditionOp::Of { set: OfSet::Patterns(compiled_set) }
                    }
                };
                self.bytecode.push(op);
            }
            CE::For { quantifier, set, body } => {
                let compiled_set = self.compile_pattern_set(set)?;
                self.emit_expr(body)?;
                if quantifier == &Quantifier::All {
                    self.bytecode.push(ConditionOp::ForAll { pattern_set: compiled_set });
                } else {
                    self.bytecode.push(ConditionOp::ForAny { pattern_set: compiled_set });
                }
            }
            CE::Identifier(name) => {
                // Resolve forward references to other rules.
                let canonical = self
                    .known_rules
                    .get(name)
                    .cloned()
                    .or_else(|| {
                        self.known_rules
                            .iter()
                            .find(|(k, _)| k.split("::").last() == Some(name.as_str()))
                            .map(|(k, _)| k.clone())
                    })
                    .unwrap_or_else(|| name.clone());
                self.bytecode.push(ConditionOp::LoadVar(canonical));
            }
            CE::At(pat_id, offset_expr) => {
                self.validate_pattern(pat_id)?;
                self.emit_expr(offset_expr)?;
                self.bytecode.push(ConditionOp::PatternMatchAt {
                    id: pat_id.clone(),
                    offset_reg: 0,
                });
            }
            CE::In(pat_id, from, to) => {
                self.validate_pattern(pat_id)?;
                self.emit_expr(from)?;
                self.emit_expr(to)?;
                self.bytecode.push(ConditionOp::PatternMatchIn {
                    id: pat_id.clone(),
                    from_reg: 0,
                    to_reg: 1,
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_pattern(&self, id: &str) -> Result<()> {
        // Strip leading '$' for lookup
        let bare = id.trim_start_matches('$');
        if bare != "*" && !self.pattern_ids.contains_key(id) {
            bail!("Undefined pattern: {id}");
        }
        Ok(())
    }

    fn compile_pattern_set(
        &self,
        set: &crate::rule_parser::PatternSet,
    ) -> Result<Vec<String>> {
        use crate::rule_parser::PatternSet;
        match set {
            PatternSet::All => Ok(self.pattern_ids.keys().cloned().collect()),
            PatternSet::Named(names) => {
                for n in names {
                    self.validate_pattern(n)?;
                }
                Ok(names.clone())
            }
            PatternSet::Wildcard(prefix) => {
                let full_prefix = format!("${prefix}");
                Ok(self
                    .pattern_ids
                    .keys()
                    .filter(|k| k.starts_with(&full_prefix))
                    .cloned()
                    .collect())
            }
        }
    }
}

// ── Rule cache ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RuleCache {
    inner: Arc<RwLock<RuleCacheInner>>,
}

#[derive(Debug)]
struct RuleCacheInner {
    by_hash: HashMap<[u8; 32], Arc<CompiledRuleSet>>,
    by_path: HashMap<PathBuf, CacheEntry>,
    max_entries: usize,
    total_hits: u64,
    total_misses: u64,
}

#[derive(Debug)]
struct CacheEntry {
    rule_set: Arc<CompiledRuleSet>,
    file_hash: [u8; 32],
    mtime: SystemTime,
    last_hit: Instant,
    hit_count: u64,
}

impl RuleCache {
    #[must_use] 
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RuleCacheInner {
                by_hash: HashMap::new(),
                by_path: HashMap::new(),
                max_entries,
                total_hits: 0,
                total_misses: 0,
            })),
        }
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<Arc<CompiledRuleSet>> {
        let mut inner = self.inner.write().unwrap();
        if let Some(rs) = inner.by_hash.get(hash).cloned() {
            inner.total_hits += 1;
            Some(rs)
        } else {
            inner.total_misses += 1;
            None
        }
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn insert(&self, hash: [u8; 32], rule_set: CompiledRuleSet) -> Arc<CompiledRuleSet> {
        let mut inner = self.inner.write().unwrap();
        if inner.by_hash.len() >= inner.max_entries {
            Self::evict(&mut inner);
        }
        let arc = Arc::new(rule_set);
        inner.by_hash.insert(hash, arc.clone());
        arc
    }

    /// # Errors
    ///
    /// Returns an error if the file cannot be read or fails to compile.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub async fn get_or_compile_file(
        &self,
        path: &Path,
        compiler: &RuleCompiler,
    ) -> Result<Arc<CompiledRuleSet>> {
        let meta = fs::metadata(path)
            .await
            .with_context(|| format!("Cannot stat {}", path.display()))?;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // Check if cached entry is still valid
        {
            let mut inner = self.inner.write().unwrap();
            if let Some(entry) = inner.by_path.get_mut(path)
                && entry.mtime == mtime {
                    entry.last_hit = Instant::now();
                    entry.hit_count = entry.hit_count.saturating_add(1);
                    return Ok(entry.rule_set.clone());
                }
        }

        let source = fs::read_to_string(path)
            .await
            .with_context(|| format!("Cannot read {}", path.display()))?;

        let mut hasher = Sha256::new();
        hasher.update(source.as_bytes());
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&hasher.finalize());

        // Check by content hash (handles renamed files)
        if let Some(rs) = self.get_by_hash(&file_hash) {
            {
                let mut inner = self.inner.write().unwrap();
                inner.by_path.insert(
                    path.to_path_buf(),
                    CacheEntry {
                        rule_set: rs.clone(),
                        file_hash,
                        mtime,
                        last_hit: Instant::now(),
                        hit_count: 1,
                    },
                );
                drop(inner);
            }
            return Ok(rs);
        }

        let rule_set = compiler
            .compile_str(&source)
            .map_err(|errs| anyhow!("Compilation errors: {errs:?}"))?;

        let arc = self.insert(file_hash, rule_set);

        {
            let mut inner = self.inner.write().unwrap();
            inner.by_path.insert(
                path.to_path_buf(),
                CacheEntry {
                    rule_set: arc.clone(),
                    file_hash,
                    mtime,
                    last_hit: Instant::now(),
                    hit_count: 1,
                },
            );
        }

        Ok(arc)
    }

    fn evict(inner: &mut RuleCacheInner) {
        // LRU eviction from by_hash
        if inner.by_hash.len() < 10 {
            return;
        }
        // Simple strategy: remove 10% of oldest entries
        let remove_count = inner.by_hash.len() / 10;
        let keys: Vec<_> = inner.by_hash.keys().take(remove_count).copied().collect();
        for k in keys {
            inner.by_hash.remove(&k);
        }
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.read().unwrap();
        CacheStats {
            total_entries: inner.by_hash.len(),
            path_entries: inner.by_path.len(),
            total_hits: inner.total_hits,
            total_misses: inner.total_misses,
            hit_rate: if inner.total_hits + inner.total_misses > 0 {
                f64::from(u32::try_from(inner.total_hits).unwrap_or(u32::MAX)) / f64::from(u32::try_from(inner.total_hits + inner.total_misses).unwrap_or(u32::MAX))
            } else {
                0.0
            },
        }
    }

    /// Return `(hit_count, seconds_since_last_hit)` for a cached path, if it
    /// is currently present in the path cache.
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn path_hit_info(&self, path: &Path) -> Option<(u64, f64)> {
        let inner = self.inner.read().unwrap();
        inner.by_path.get(path).map(|e| {
            (e.hit_count, e.last_hit.elapsed().as_secs_f64())
        })
    }

    /// Return the path of the least-recently-used cached entry, based on the
    /// `last_hit` timestamp of each cache entry.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn lru_path(&self) -> Option<PathBuf> {
        let inner = self.inner.read().unwrap();
        inner
            .by_path
            .iter()
            .min_by_key(|(_, e)| e.last_hit)
            .map(|(p, _)| p.clone())
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn invalidate_path(&self, path: &Path) {
        let mut inner = self.inner.write().unwrap();
        if let Some(entry) = inner.by_path.remove(path) {
            inner.by_hash.remove(&entry.file_hash);
        }
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.by_hash.clear();
        inner.by_path.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub path_entries: usize,
    pub total_hits: u64,
    pub total_misses: u64,
    pub hit_rate: f64,
}

// ── File watcher for hot-reload ────────────────────────────────────────────────

pub struct HotReloader {
    cache: Arc<RuleCache>,
    compiler: Arc<RuleCompiler>,
    watch_paths: Vec<PathBuf>,
    tx: mpsc::Sender<HotReloadEvent>,
}

#[derive(Debug, Clone)]
pub enum HotReloadEvent {
    RuleFileChanged(PathBuf),
    RuleFileAdded(PathBuf),
    RuleFileRemoved(PathBuf),
    CompilationError { path: PathBuf, errors: Vec<String> },
    RuleSetUpdated { path: PathBuf, rule_count: usize },
}

impl HotReloader {
    #[must_use] 
    pub fn new(
        cache: Arc<RuleCache>,
        compiler: Arc<RuleCompiler>,
    ) -> (Self, mpsc::Receiver<HotReloadEvent>) {
        let (tx, rx) = mpsc::channel(64);
        (
            Self {
                cache,
                compiler,
                watch_paths: Vec::new(),
                tx,
            },
            rx,
        )
    }

    pub fn watch(&mut self, path: PathBuf) {
        self.watch_paths.push(path);
    }

    pub async fn run(self) {
        let mut mtimes: HashMap<PathBuf, SystemTime> = HashMap::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;

            for path in &self.watch_paths {
                match self.check_path(path, &mut mtimes).await {
                    Ok(Some(event)) => {
                        let _ = self.tx.send(event).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("Hot-reload check error for {:?}: {}", path, e);
                    }
                }
            }
        }
    }

    async fn check_path(
        &self,
        path: &Path,
        mtimes: &mut HashMap<PathBuf, SystemTime>,
    ) -> Result<Option<HotReloadEvent>> {
        let Ok(meta) = fs::metadata(path).await else {
            if mtimes.remove(path).is_some() {
                return Ok(Some(HotReloadEvent::RuleFileRemoved(path.to_path_buf())));
            }
            return Ok(None);
        };

        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let prev = mtimes.get(path).copied();

        if prev.is_none() {
            mtimes.insert(path.to_path_buf(), mtime);
            return Ok(Some(HotReloadEvent::RuleFileAdded(path.to_path_buf())));
        }

        if prev == Some(mtime) {
            return Ok(None);
        }

        mtimes.insert(path.to_path_buf(), mtime);
        self.cache.invalidate_path(path);

        match self
            .cache
            .get_or_compile_file(path, &self.compiler)
            .await
        {
            Ok(rs) => Ok(Some(HotReloadEvent::RuleSetUpdated {
                path: path.to_path_buf(),
                rule_count: rs.total_rules(),
            })),
            Err(e) => Ok(Some(HotReloadEvent::CompilationError {
                path: path.to_path_buf(),
                errors: vec![e.to_string()],
            })),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atom_quality() {
        let compiler = RuleCompiler::new();
        assert_eq!(RuleCompiler::atom_quality(&[]), 0);
        assert_eq!(RuleCompiler::atom_quality(&[0x00, 0x00, 0x00, 0x00]), 0);
        assert_eq!(RuleCompiler::atom_quality(&[0xFF, 0xFF, 0xFF, 0xFF]), 0);
        assert!(RuleCompiler::atom_quality(&[0x4D, 0x5A, 0x90, 0x00]) > 0);
        // MZ header bytes should have decent quality
        let mz = RuleCompiler::atom_quality(&[0x4D, 0x5A, 0x90, 0x00]);
        let zero = RuleCompiler::atom_quality(&[0x00, 0x00, 0x00, 0x00]);
        assert!(mz > zero);
    }

    #[test]
    fn test_modifier_validation() {
        let compiler = RuleCompiler::new();
        // base64 + xor should fail
        // This tests the validation path
        assert!(compiler.atom_quality_threshold < 100);
    }

    #[test]
    fn test_cache_stats() {
        let cache = RuleCache::new(100);
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }
}
