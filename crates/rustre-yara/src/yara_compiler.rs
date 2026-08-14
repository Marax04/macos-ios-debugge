//! YARA rule compiler — translates parsed YARA rules into internal bytecode.
//!
//! The compiler produces a `YaraProgram` consisting of `CompiledRule` objects.
//! Each rule contains compiled string definitions and a bytecode sequence
//! (`CompiledCondition`) that can be executed by a stack-based VM.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// String flags (bitfield)
// ---------------------------------------------------------------------------

/// Modifier flags on a YARA string definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StringFlags(pub u32);

impl StringFlags {
    pub const NOCASE:  u32 = 1 << 0;
    pub const WIDE:    u32 = 1 << 1;
    pub const ASCII:   u32 = 1 << 2;
    pub const FULLWORD:u32 = 1 << 3;
    pub const PRIVATE: u32 = 1 << 4;
    pub const XOR:     u32 = 1 << 5;
    pub const BASE64:  u32 = 1 << 6;

    pub const fn set(&mut self, flag: u32) { self.0 |= flag; }
    #[must_use] 
    pub const fn has(&self, flag: u32) -> bool { self.0 & flag != 0 }
    #[must_use] 
    pub const fn nocase(&self)   -> bool { self.has(Self::NOCASE) }
    #[must_use] 
    pub const fn wide(&self)     -> bool { self.has(Self::WIDE) }
    #[must_use] 
    pub const fn ascii(&self)    -> bool { self.has(Self::ASCII) }
    #[must_use] 
    pub const fn fullword(&self) -> bool { self.has(Self::FULLWORD) }
    #[must_use] 
    pub const fn private(&self)  -> bool { self.has(Self::PRIVATE) }
    #[must_use] 
    pub const fn xor_enc(&self)  -> bool { self.has(Self::XOR) }
    #[must_use] 
    pub const fn base64(&self)   -> bool { self.has(Self::BASE64) }
}

impl std::fmt::Display for StringFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.nocase()   { parts.push("nocase"); }
        if self.wide()     { parts.push("wide"); }
        if self.ascii()    { parts.push("ascii"); }
        if self.fullword() { parts.push("fullword"); }
        if self.private()  { parts.push("private"); }
        if self.xor_enc()  { parts.push("xor"); }
        if self.base64()   { parts.push("base64"); }
        write!(f, "{}", parts.join(" "))
    }
}

// ---------------------------------------------------------------------------
// Hex pattern tokens
// ---------------------------------------------------------------------------

/// One token in a hex pattern string (e.g. `{ DE AD ?? [2-4] (AA|BB) }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexToken {
    /// A literal byte value.
    Byte(u8),
    /// `??` wildcard — matches any byte.
    Wildcard,
    /// `[-]` unlimited jump.
    JumpAny,
    /// `[lo-hi]` bounded jump.
    Jump(u8, u8),
    /// `(aa | bb cc | ...)` alternatives.
    Alternative(Vec<Vec<Self>>),
}

// ---------------------------------------------------------------------------
// Compiled pattern
// ---------------------------------------------------------------------------

/// A compiled string pattern, ready for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledPattern {
    /// Byte-literal string, possibly encoded.
    Literal(Vec<u8>),
    /// Regular expression source string.
    Regex(String),
    /// Hex pattern token sequence.
    Hex(Vec<HexToken>),
}

// ---------------------------------------------------------------------------
// Compiled string definition
// ---------------------------------------------------------------------------

/// One compiled `$identifier = ...` string definition.
#[derive(Debug, Clone)]
pub struct CompiledStringDef {
    /// The `$id` part (without `$`).
    pub id: String,
    pub pattern: CompiledPattern,
    pub flags: StringFlags,
}

// ---------------------------------------------------------------------------
// Meta value
// ---------------------------------------------------------------------------

/// Value type in a YARA `meta:` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

// ---------------------------------------------------------------------------
// Bytecode opcodes
// ---------------------------------------------------------------------------

/// Stack-machine opcodes for the compiled condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondOp {
    /// Push an integer literal.
    PushInt(i64),
    /// Push a string literal.
    PushStr(String),
    /// Push a boolean literal.
    PushBool(bool),
    /// Logical AND of top two stack values.
    And,
    /// Logical OR of top two stack values.
    Or,
    /// Logical NOT of top stack value.
    Not,
    /// Integer equality comparison.
    CmpEq,
    /// Integer inequality comparison.
    CmpNe,
    /// Less-than comparison.
    CmpLt,
    /// Greater-than comparison.
    CmpGt,
    /// Less-than-or-equal comparison.
    CmpLe,
    /// Greater-than-or-equal comparison.
    CmpGe,
    /// Load the match-bool for string ID at index in string table.
    LoadMatch(usize),
    /// Load the match count for string ID.
    LoadCount(usize),
    /// Load the N-th match offset for string ID.
    LoadOffset(usize),
    /// Load the N-th match length for string ID.
    LoadLength(usize),
    /// Push file size.
    LoadFileSize,
    /// Push entry point (or undefined).
    LoadEntryPoint,
    /// `N of (ids...)` — pops N and set-size, pushes bool.
    Of,
    /// `for N of ids: (cond)` — pops N, pushes bool.
    For,
    /// `defined expr` — wraps next op in try block.
    Defined,
    /// Read integer at offset with given width.
    IntAt(u8),
    /// Add
    Add,
    /// Subtract
    Sub,
    /// Multiply
    Mul,
    /// Divide
    Div,
    /// Modulo
    Mod,
    /// Bitwise AND
    BitAnd,
    /// Bitwise OR
    BitOr,
    /// Bitwise XOR
    BitXor,
    /// Shift left
    Shl,
    /// Shift right
    Shr,
}

// ---------------------------------------------------------------------------
// Compiled condition
// ---------------------------------------------------------------------------

/// The bytecode representation of a rule's condition.
#[derive(Debug, Clone, Default)]
pub struct CompiledCondition {
    /// Linear sequence of stack opcodes.
    pub bytecode: Vec<CondOp>,
    /// String identifiers referenced by Load* opcodes (indexed by usize arg).
    pub string_table: Vec<String>,
}

impl CompiledCondition {
    fn new() -> Self { Self::default() }

    fn push(&mut self, op: CondOp) { self.bytecode.push(op); }

    fn intern_string(&mut self, id: &str) -> usize {
        if let Some(pos) = self.string_table.iter().position(|s| s == id) {
            return pos;
        }
        let idx = self.string_table.len();
        self.string_table.push(id.to_owned());
        idx
    }
}

// ---------------------------------------------------------------------------
// Compiled rule
// ---------------------------------------------------------------------------

/// A fully compiled YARA rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, MetaValue)>,
    pub string_defs: Vec<CompiledStringDef>,
    pub condition: CompiledCondition,
    pub is_private: bool,
    pub is_global: bool,
}

// ---------------------------------------------------------------------------
// Compiled program
// ---------------------------------------------------------------------------

/// A collection of compiled rules, the output of the compiler.
#[derive(Debug, Clone, Default)]
pub struct YaraProgram {
    pub rules: Vec<CompiledRule>,
    /// Namespace → list of rule names (for cross-rule reference resolution).
    pub namespace_index: HashMap<String, Vec<String>>,
}

impl YaraProgram {
    pub fn add_rule(&mut self, rule: CompiledRule) {
        self.namespace_index
            .entry(rule.namespace.clone())
            .or_default()
            .push(rule.name.clone());
        self.rules.push(rule);
    }

    #[must_use] 
    pub const fn rule_count(&self) -> usize { self.rules.len() }

    #[must_use] 
    pub fn find_rule(&self, name: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.name == name)
    }
}

// ---------------------------------------------------------------------------
// Compile error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    UnknownStringId(String),
    InvalidHexPattern(String),
    InvalidRegex(String),
    DuplicateRuleName(String),
    DuplicateStringId(String),
    ParseError { line: usize, message: String },
    UnsupportedFeature(String),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownStringId(s)     => write!(f, "unknown string id: {s}"),
            Self::InvalidHexPattern(s)   => write!(f, "invalid hex pattern: {s}"),
            Self::InvalidRegex(s)        => write!(f, "invalid regex: {s}"),
            Self::DuplicateRuleName(s)   => write!(f, "duplicate rule name: {s}"),
            Self::DuplicateStringId(s)   => write!(f, "duplicate string id: {s}"),
            Self::ParseError { line, message } => write!(f, "parse error at line {line}: {message}"),
            Self::UnsupportedFeature(s)  => write!(f, "unsupported feature: {s}"),
        }
    }
}
impl std::error::Error for CompileError {}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

/// YARA rule compiler.
pub struct YaraCompiler {
    program: YaraProgram,
    current_namespace: String,
}

impl YaraCompiler {
    #[must_use] 
    pub fn new() -> Self {
        Self { program: YaraProgram::default(), current_namespace: "default".to_owned() }
    }

    pub fn set_namespace(&mut self, ns: &str) {
        ns.clone_into(&mut self.current_namespace);
    }

    /// Compile a single rule from its constituent parts.
    ///
    /// # Errors
    ///
    /// Returns a [`CompileError`] if the rule name is a duplicate, any string
    /// definition is invalid, or the condition fails to compile.
    pub fn compile_rule(
        &mut self,
        name: &str,
        tags: Vec<String>,
        meta: Vec<(String, MetaValue)>,
        string_defs: Vec<RawStringDef>,
        condition_src: &str,
        flags: &RuleFlags,
    ) -> Result<(), CompileError> {
        // Check duplicate names
        if self.program.find_rule(name).is_some() {
            return Err(CompileError::DuplicateRuleName(name.to_owned()));
        }

        // Compile string definitions
        let mut compiled_strings = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        for def in string_defs {
            if !seen_ids.insert(def.id.clone()) {
                return Err(CompileError::DuplicateStringId(def.id));
            }
            let pattern = Self::compile_pattern(&def)?;
            compiled_strings.push(CompiledStringDef {
                id: def.id,
                pattern,
                flags: def.flags,
            });
        }

        // Compile condition
        let condition = self.compile_condition(condition_src, &compiled_strings)?;

        self.program.add_rule(CompiledRule {
            name: name.to_owned(),
            namespace: self.current_namespace.clone(),
            tags,
            meta,
            string_defs: compiled_strings,
            condition,
            is_private: flags.private,
            is_global: flags.global,
        });
        Ok(())
    }

    fn compile_pattern(def: &RawStringDef) -> Result<CompiledPattern, CompileError> {
        match def.kind {
            PatternKind::Literal => {
                Ok(CompiledPattern::Literal(def.value.as_bytes().to_vec()))
            }
            PatternKind::Regex => {
                // Basic regex validation: must start and end with '/'
                let v = def.value.trim();
                if !v.starts_with('/') || !v.ends_with('/') {
                    return Err(CompileError::InvalidRegex(def.value.clone()));
                }
                Ok(CompiledPattern::Regex(v[1..v.len()-1].to_owned()))
            }
            PatternKind::Hex => {
                let tokens = parse_hex_pattern(&def.value)
                    .map_err(CompileError::InvalidHexPattern)?;
                Ok(CompiledPattern::Hex(tokens))
            }
        }
    }

    /// Compile a condition string to a `CompiledCondition`.
    ///
    /// This is a simplified compiler that handles the most common forms.
    /// Production use would replace this with a full recursive-descent parser.
    ///
    /// # Errors
    ///
    /// Returns a [`CompileError`] if the condition expression is invalid.
    pub fn compile_condition(
        &self,
        src: &str,
        string_defs: &[CompiledStringDef],
    ) -> Result<CompiledCondition, CompileError> {
        let mut cc = CompiledCondition::new();
        let tokens = tokenize_condition(src);
        compile_expr_tokens(&tokens, &mut cc, string_defs)?;
        Ok(cc)
    }

    #[must_use] 
    pub fn finish(self) -> YaraProgram { self.program }
}

impl Default for YaraCompiler {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Rule flags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct RuleFlags {
    pub private: bool,
    pub global: bool,
}

// ---------------------------------------------------------------------------
// Raw string definition (input to compiler)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RawStringDef {
    pub id: String,
    pub value: String,
    pub kind: PatternKind,
    pub flags: StringFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Literal,
    Regex,
    Hex,
}

// ---------------------------------------------------------------------------
// Hex pattern parser
// ---------------------------------------------------------------------------

fn parse_hex_pattern(src: &str) -> Result<Vec<HexToken>, String> {
    let inner = src.trim().trim_start_matches('{').trim_end_matches('}').trim();
    let mut tokens = Vec::new();
    let mut chars = inner.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => { chars.next(); }
            '?' => {
                chars.next();
                if chars.peek() == Some(&'?') { chars.next(); }
                tokens.push(HexToken::Wildcard);
            }
            '[' => {
                chars.next();
                let mut lo_s = String::new();
                let mut hi_s = String::new();
                let mut in_hi = false;
                let mut is_any = false;
                while let Some(&c) = chars.peek() {
                    chars.next();
                    match c {
                        ']' => break,
                        '-' => {
                            if lo_s.is_empty() { is_any = true; }
                            else { in_hi = true; }
                        }
                        d if d.is_ascii_digit() => {
                            if in_hi { hi_s.push(d); } else { lo_s.push(d); }
                        }
                        _ => return Err(format!("unexpected char in jump: {c}")),
                    }
                }
                if is_any {
                    tokens.push(HexToken::JumpAny);
                } else {
                    let lo: u8 = lo_s.parse().map_err(|_| "bad jump lo".to_owned())?;
                    let hi: u8 = if hi_s.is_empty() { lo } else {
                        hi_s.parse().map_err(|_| "bad jump hi".to_owned())?
                    };
                    tokens.push(HexToken::Jump(lo, hi));
                }
            }
            '(' => {
                chars.next();
                let mut alts: Vec<Vec<HexToken>> = vec![vec![]];
                let mut buf = String::new();
                let mut depth = 1;
                while let Some(&c) = chars.peek() {
                    chars.next();
                    match c {
                        '(' => { depth += 1; buf.push(c); }
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                let sub = parse_hex_pattern(&format!("{{ {buf} }}"))?;
                                *alts.last_mut().unwrap() = sub;
                                break;
                            }
                            buf.push(c);
                        }
                        '|' if depth == 1 => {
                            let sub = parse_hex_pattern(&format!("{{ {buf} }}"))?;
                            *alts.last_mut().unwrap() = sub;
                            alts.push(vec![]);
                            buf.clear();
                        }
                        _ => buf.push(c),
                    }
                }
                tokens.push(HexToken::Alternative(alts));
            }
            c if c.is_ascii_hexdigit() => {
                chars.next();
                let hi = c;
                let lo = chars.next().ok_or_else(|| "truncated hex byte".to_owned())?;
                let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16)
                    .map_err(|_| format!("bad hex byte {hi}{lo}"))?;
                tokens.push(HexToken::Byte(byte));
            }
            other => return Err(format!("unexpected character in hex pattern: {other}")),
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Condition tokenizer (very simplified)
// ---------------------------------------------------------------------------

fn tokenize_condition(src: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = src.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => {
                if !cur.is_empty() { tokens.push(cur.clone()); cur.clear(); }
            }
            '=' if chars.peek() == Some(&'=') => {
                chars.next();
                if !cur.is_empty() { tokens.push(cur.clone()); cur.clear(); }
                tokens.push("==".to_owned());
            }
            '!' if chars.peek() == Some(&'=') => {
                chars.next();
                if !cur.is_empty() { tokens.push(cur.clone()); cur.clear(); }
                tokens.push("!=".to_owned());
            }
            '<' if chars.peek() == Some(&'=') => {
                chars.next();
                if !cur.is_empty() { tokens.push(cur.clone()); cur.clear(); }
                tokens.push("<=".to_owned());
            }
            '>' if chars.peek() == Some(&'=') => {
                chars.next();
                if !cur.is_empty() { tokens.push(cur.clone()); cur.clear(); }
                tokens.push(">=".to_owned());
            }
            '(' | ')' | ',' | '<' | '>' => {
                if !cur.is_empty() { tokens.push(cur.clone()); cur.clear(); }
                tokens.push(ch.to_string());
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() { tokens.push(cur); }
    tokens
}

fn compile_expr_tokens(
    tokens: &[String],
    cc: &mut CompiledCondition,
    strings: &[CompiledStringDef],
) -> Result<(), CompileError> {
    if tokens.is_empty() { return Ok(()); }

    // Simple single-token cases
    if tokens.len() == 1 {
        return compile_single_token(&tokens[0], cc, strings);
    }

    // `not X`
    if tokens[0] == "not" {
        compile_expr_tokens(&tokens[1..], cc, strings)?;
        cc.push(CondOp::Not);
        return Ok(());
    }

    // `X and Y`, `X or Y`
    if let Some(and_pos) = tokens.iter().position(|t| t == "and") {
        compile_expr_tokens(&tokens[..and_pos], cc, strings)?;
        compile_expr_tokens(&tokens[and_pos + 1..], cc, strings)?;
        cc.push(CondOp::And);
        return Ok(());
    }
    if let Some(or_pos) = tokens.iter().position(|t| t == "or") {
        compile_expr_tokens(&tokens[..or_pos], cc, strings)?;
        compile_expr_tokens(&tokens[or_pos + 1..], cc, strings)?;
        cc.push(CondOp::Or);
        return Ok(());
    }

    // Comparison operators
    for op_str in &["==", "!=", "<=", ">=", "<", ">"] {
        if let Some(pos) = tokens.iter().position(|t| t == *op_str) {
            compile_expr_tokens(&tokens[..pos], cc, strings)?;
            compile_expr_tokens(&tokens[pos + 1..], cc, strings)?;
            cc.push(match *op_str {
                "==" => CondOp::CmpEq,
                "!=" => CondOp::CmpNe,
                "<"  => CondOp::CmpLt,
                ">"  => CondOp::CmpGt,
                "<=" => CondOp::CmpLe,
                ">=" => CondOp::CmpGe,
                _    => unreachable!(),
            });
            return Ok(());
        }
    }

    // Arithmetic
    for op_str in &["+", "-", "*", "/", "%"] {
        if let Some(pos) = tokens.iter().position(|t| t == *op_str) {
            compile_expr_tokens(&tokens[..pos], cc, strings)?;
            compile_expr_tokens(&tokens[pos + 1..], cc, strings)?;
            cc.push(match *op_str {
                "+" => CondOp::Add,
                "-" => CondOp::Sub,
                "*" => CondOp::Mul,
                "/" => CondOp::Div,
                "%" => CondOp::Mod,
                _   => unreachable!(),
            });
            return Ok(());
        }
    }

    // `any of ($a, $b, ...)`
    if tokens.len() >= 3 && (tokens[0] == "any" || tokens[0] == "all" || tokens[0] == "none")
        && tokens[1] == "of"
    {
        let total = strings.len();
        cc.push(CondOp::PushInt(i64::try_from(total).unwrap_or(i64::MAX)));
        for s in strings {
            let idx = cc.intern_string(&s.id);
            cc.push(CondOp::LoadMatch(idx));
        }
        cc.push(CondOp::Of);
        return Ok(());
    }

    // `filesize`
    if tokens[0] == "filesize" && tokens.len() == 1 {
        cc.push(CondOp::LoadFileSize);
        return Ok(());
    }

    // Fallback: try first token
    compile_single_token(&tokens[0], cc, strings)?;
    Ok(())
}

fn compile_single_token(
    tok: &str,
    cc: &mut CompiledCondition,
    strings: &[CompiledStringDef],
) -> Result<(), CompileError> {
    match tok {
        "true"      => { cc.push(CondOp::PushBool(true));  return Ok(()); }
        "false"     => { cc.push(CondOp::PushBool(false)); return Ok(()); }
        "filesize"  => { cc.push(CondOp::LoadFileSize);    return Ok(()); }
        "entrypoint"=> { cc.push(CondOp::LoadEntryPoint);  return Ok(()); }
        _ => {}
    }

    // Integer literal
    if let Ok(n) = tok.parse::<i64>() {
        cc.push(CondOp::PushInt(n));
        return Ok(());
    }
    // Hex integer literal
    if tok.starts_with("0x")
        && let Ok(n) = i64::from_str_radix(&tok[2..], 16) {
            cc.push(CondOp::PushInt(n));
            return Ok(());
        }

    // `$id` — pattern match
    if let Some(id) = tok.strip_prefix('$') {
        let found = strings.iter().find(|s| s.id == id);
        if let Some(s) = found {
            let idx = cc.intern_string(&s.id);
            cc.push(CondOp::LoadMatch(idx));
        } else {
            return Err(CompileError::UnknownStringId(tok.to_owned()));
        }
        return Ok(());
    }

    // `#id` — count
    if let Some(id) = tok.strip_prefix('#') {
        let found = strings.iter().find(|s| s.id == id);
        if let Some(s) = found {
            let idx = cc.intern_string(&s.id);
            cc.push(CondOp::LoadCount(idx));
        } else {
            return Err(CompileError::UnknownStringId(tok.to_owned()));
        }
        return Ok(());
    }

    // String literal
    if tok.starts_with('"') && tok.ends_with('"') {
        cc.push(CondOp::PushStr(tok[1..tok.len()-1].to_owned()));
        return Ok(());
    }

    // Identifier (rule reference, variable)
    cc.push(CondOp::PushStr(tok.to_owned()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_string_def(id: &str, value: &str) -> RawStringDef {
        RawStringDef {
            id: id.to_owned(),
            value: value.to_owned(),
            kind: PatternKind::Literal,
            flags: StringFlags::default(),
        }
    }

    fn make_hex_def(id: &str, hex: &str) -> RawStringDef {
        RawStringDef {
            id: id.to_owned(),
            value: hex.to_owned(),
            kind: PatternKind::Hex,
            flags: StringFlags::default(),
        }
    }

    #[test]
    fn test_compile_simple_rule() {
        let mut compiler = YaraCompiler::new();
        let defs = vec![make_string_def("a", "MZ")];
        compiler.compile_rule("TestRule", vec![], vec![], defs, "$a", &RuleFlags::default()).unwrap();
        let prog = compiler.finish();
        assert_eq!(prog.rule_count(), 1);
        assert_eq!(prog.rules[0].name, "TestRule");
    }

    #[test]
    fn test_duplicate_rule_name() {
        let mut compiler = YaraCompiler::new();
        let defs = vec![make_string_def("a", "MZ")];
        compiler.compile_rule("Dup", vec![], vec![], defs.clone(), "$a", &RuleFlags::default()).unwrap();
        let result = compiler.compile_rule("Dup", vec![], vec![], defs, "$a", &RuleFlags::default());
        assert!(matches!(result, Err(CompileError::DuplicateRuleName(_))));
    }

    #[test]
    fn test_duplicate_string_id() {
        let mut compiler = YaraCompiler::new();
        let defs = vec![
            make_string_def("a", "MZ"),
            make_string_def("a", "ZM"),
        ];
        let result = compiler.compile_rule("Test", vec![], vec![], defs, "$a", &RuleFlags::default());
        assert!(matches!(result, Err(CompileError::DuplicateStringId(_))));
    }

    #[test]
    fn test_string_flags_nocase() {
        let mut f = StringFlags::default();
        f.set(StringFlags::NOCASE);
        assert!(f.nocase());
        assert!(!f.wide());
    }

    #[test]
    fn test_string_flags_display() {
        let mut f = StringFlags::default();
        f.set(StringFlags::NOCASE | StringFlags::WIDE);
        let s = f.to_string();
        assert!(s.contains("nocase"));
        assert!(s.contains("wide"));
    }

    #[test]
    fn test_hex_pattern_simple() {
        let tokens = parse_hex_pattern("{ DE AD BE EF }").unwrap();
        assert_eq!(tokens, vec![
            HexToken::Byte(0xDE),
            HexToken::Byte(0xAD),
            HexToken::Byte(0xBE),
            HexToken::Byte(0xEF),
        ]);
    }

    #[test]
    fn test_hex_pattern_wildcard() {
        let tokens = parse_hex_pattern("{ DE ?? EF }").unwrap();
        assert!(matches!(tokens[1], HexToken::Wildcard));
    }

    #[test]
    fn test_hex_pattern_jump() {
        let tokens = parse_hex_pattern("{ DE [1-3] EF }").unwrap();
        assert!(matches!(tokens[1], HexToken::Jump(1, 3)));
    }

    #[test]
    fn test_hex_pattern_jump_any() {
        let tokens = parse_hex_pattern("{ DE [-] EF }").unwrap();
        assert!(matches!(tokens[1], HexToken::JumpAny));
    }

    #[test]
    fn test_compile_condition_true() {
        let compiler = YaraCompiler::new();
        let cc = compiler.compile_condition("true", &[]).unwrap();
        assert_eq!(cc.bytecode, vec![CondOp::PushBool(true)]);
    }

    #[test]
    fn test_compile_condition_filesize() {
        let compiler = YaraCompiler::new();
        let cc = compiler.compile_condition("filesize", &[]).unwrap();
        assert_eq!(cc.bytecode, vec![CondOp::LoadFileSize]);
    }

    #[test]
    fn test_compile_condition_and() {
        let compiler = YaraCompiler::new();
        let cc = compiler.compile_condition("true and false", &[]).unwrap();
        assert!(cc.bytecode.contains(&CondOp::And));
    }

    #[test]
    fn test_compile_condition_or() {
        let compiler = YaraCompiler::new();
        let cc = compiler.compile_condition("true or false", &[]).unwrap();
        assert!(cc.bytecode.contains(&CondOp::Or));
    }

    #[test]
    fn test_compile_condition_not() {
        let compiler = YaraCompiler::new();
        let cc = compiler.compile_condition("not false", &[]).unwrap();
        assert!(cc.bytecode.contains(&CondOp::Not));
    }

    #[test]
    fn test_compile_condition_pattern_ref() {
        let compiler = YaraCompiler::new();
        let strings = vec![CompiledStringDef {
            id: "mz".to_owned(),
            pattern: CompiledPattern::Literal(vec![b'M', b'Z']),
            flags: StringFlags::default(),
        }];
        let cc = compiler.compile_condition("$mz", &strings).unwrap();
        assert!(!cc.bytecode.is_empty());
        assert!(matches!(cc.bytecode[0], CondOp::LoadMatch(_)));
    }

    #[test]
    fn test_compile_condition_unknown_string() {
        let compiler = YaraCompiler::new();
        let result = compiler.compile_condition("$unknown", &[]);
        assert!(matches!(result, Err(CompileError::UnknownStringId(_))));
    }

    #[test]
    fn test_namespace() {
        let mut compiler = YaraCompiler::new();
        compiler.set_namespace("malware");
        let defs = vec![make_string_def("a", "bad")];
        compiler.compile_rule("EvilRule", vec![], vec![], defs, "$a", &RuleFlags::default()).unwrap();
        let prog = compiler.finish();
        assert_eq!(prog.rules[0].namespace, "malware");
    }

    #[test]
    fn test_meta_values() {
        let mut compiler = YaraCompiler::new();
        let meta = vec![
            ("author".to_owned(), MetaValue::Str("alice".to_owned())),
            ("score".to_owned(), MetaValue::Int(80)),
            ("active".to_owned(), MetaValue::Bool(true)),
        ];
        compiler.compile_rule("MetaRule", vec![], meta, vec![], "true", &RuleFlags::default()).unwrap();
        let prog = compiler.finish();
        assert_eq!(prog.rules[0].meta.len(), 3);
    }

    #[test]
    fn test_tags() {
        let mut compiler = YaraCompiler::new();
        let tags = vec!["ransomware".to_owned(), "cryptolocker".to_owned()];
        compiler.compile_rule("TagRule", tags, vec![], vec![], "true", &RuleFlags::default()).unwrap();
        let prog = compiler.finish();
        assert_eq!(prog.rules[0].tags.len(), 2);
    }

    #[test]
    fn test_hex_def_compiles() {
        let mut compiler = YaraCompiler::new();
        let defs = vec![make_hex_def("sig", "{ 4D 5A ?? ?? }") ];
        compiler.compile_rule("HexRule", vec![], vec![], defs, "$sig", &RuleFlags::default()).unwrap();
        let prog = compiler.finish();
        assert!(matches!(prog.rules[0].string_defs[0].pattern, CompiledPattern::Hex(_)));
    }
}
