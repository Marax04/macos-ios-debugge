//! YARA condition evaluator: runs a parsed [`Condition`] AST against file bytes.
//!
//! Provides [`ConditionEval`], [`EvalContext`], and the full operator set.

use std::collections::HashMap;

use crate::YaraError;
use crate::rule_parser::{Condition, HexByte, StringSet, YaraRule, YaraString, YaraStringKind};

// ─── MatchResult ──────────────────────────────────────────────────────────────

/// The location(s) of a string match within file data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchLocation {
    pub offset: usize,
    pub length: usize,
}

/// All matches for a given string identifier.
#[derive(Debug, Clone, Default)]
pub struct StringMatches {
    pub locations: Vec<MatchLocation>,
}

impl StringMatches {
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.locations.len()
    }

    #[must_use] 
    pub const fn matched(&self) -> bool {
        !self.locations.is_empty()
    }

    #[must_use] 
    pub fn at_offset(&self, offset: usize) -> bool {
        self.locations.iter().any(|l| l.offset == offset)
    }

    #[must_use] 
    pub fn in_range(&self, lo: usize, hi: usize) -> bool {
        self.locations
            .iter()
            .any(|l| l.offset >= lo && l.offset <= hi)
    }
}

// ─── EvalContext ──────────────────────────────────────────────────────────────

/// The evaluation context: file data, pre-computed string matches, module values.
pub struct EvalContext<'a> {
    /// The raw file bytes being scanned.
    pub file: &'a [u8],
    /// Pre-computed string matches keyed by string identifier (e.g. "$a").
    pub matches: HashMap<String, StringMatches>,
    /// Entry point offset in the file, if known.
    pub entrypoint: Option<usize>,
    /// Module stubs: (module, field) → integer value.
    pub module_ints: HashMap<(String, String), i64>,
    /// Module stubs: (module, field) → string value.
    pub module_strs: HashMap<(String, String), String>,
    /// Module stubs: (module, field) → bool.
    pub module_bools: HashMap<(String, String), bool>,
}

impl<'a> EvalContext<'a> {
    #[must_use] 
    pub fn new(file: &'a [u8]) -> Self {
        Self {
            file,
            matches: HashMap::new(),
            entrypoint: None,
            module_ints: HashMap::new(),
            module_strs: HashMap::new(),
            module_bools: HashMap::new(),
        }
    }

    #[must_use] 
    pub const fn with_entrypoint(mut self, ep: usize) -> Self {
        self.entrypoint = Some(ep);
        self
    }

    /// Add a pre-computed match for a string identifier.
    pub fn add_match(&mut self, ident: &str, offset: usize, length: usize) {
        self.matches
            .entry(ident.to_string())
            .or_default()
            .locations
            .push(MatchLocation { offset, length });
    }

    #[must_use]
    pub fn filesize(&self) -> i64 {
        i64::try_from(self.file.len()).unwrap_or(i64::MAX)
    }

    #[must_use]
    pub fn entrypoint_val(&self) -> i64 {
        i64::try_from(self.entrypoint.unwrap_or(0)).unwrap_or(i64::MAX)
    }
}

// ─── Value ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    Undef,
}

impl Value {
    const fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Str(s) => !s.is_empty(),
            Self::Undef => false,
        }
    }

    fn as_int(&self) -> i64 {
        match self {
            Self::Int(i) => *i,
            Self::Bool(b) => i64::from(*b),
            _ => 0,
        }
    }

    const fn as_str(&self) -> &str {
        match self {
            Self::Str(s) => s.as_str(),
            _ => "",
        }
    }
}

// ─── ConditionEval ────────────────────────────────────────────────────────────

/// Evaluates a YARA condition against an [`EvalContext`].
pub struct ConditionEval;

impl ConditionEval {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate a condition. Returns `true` if the rule matches.
    ///
    /// # Errors
    ///
    /// Returns a [`YaraError`] for type errors (division by zero, type mismatch).
    pub fn eval(&self, cond: &Condition, ctx: &EvalContext<'_>) -> Result<bool, YaraError> {
        Ok(self.eval_value(cond, ctx)?.as_bool())
    }

    fn eval_value(&self, cond: &Condition, ctx: &EvalContext<'_>) -> Result<Value, YaraError> {
        match cond {
            Condition::Bool(b) => Ok(Value::Bool(*b)),
            Condition::Int(i) => Ok(Value::Int(*i)),
            Condition::Str(s) => Ok(Value::Str(s.clone())),
            Condition::Filesize => Ok(Value::Int(ctx.filesize())),
            Condition::Entrypoint => Ok(Value::Int(ctx.entrypoint_val())),
            Condition::Not(inner) => Ok(Value::Bool(!self.eval_value(inner, ctx)?.as_bool())),
            Condition::And(left, right) => {
                if !self.eval_value(left, ctx)?.as_bool() { return Ok(Value::Bool(false)); }
                Ok(Value::Bool(self.eval_value(right, ctx)?.as_bool()))
            }
            Condition::Or(left, right) => {
                if self.eval_value(left, ctx)?.as_bool() { return Ok(Value::Bool(true)); }
                Ok(Value::Bool(self.eval_value(right, ctx)?.as_bool()))
            }
            Condition::Eq(l, r) => {
                let (lv, rv) = (self.eval_value(l, ctx)?, self.eval_value(r, ctx)?);
                Ok(Value::Bool(match (&lv, &rv) {
                    (Value::Int(a), Value::Int(b)) => a == b,
                    (Value::Str(a), Value::Str(b)) => a == b,
                    (Value::Bool(a), Value::Bool(b)) => a == b,
                    _ => false,
                }))
            }
            Condition::Ne(l, r) => {
                let (lv, rv) = (self.eval_value(l, ctx)?, self.eval_value(r, ctx)?);
                Ok(Value::Bool(match (&lv, &rv) {
                    (Value::Int(a), Value::Int(b)) => a != b,
                    (Value::Str(a), Value::Str(b)) => a != b,
                    _ => true,
                }))
            }
            Condition::Lt(l, r) => Ok(Value::Bool(self.eval_value(l, ctx)?.as_int() < self.eval_value(r, ctx)?.as_int())),
            Condition::Le(l, r) => Ok(Value::Bool(self.eval_value(l, ctx)?.as_int() <= self.eval_value(r, ctx)?.as_int())),
            Condition::Gt(l, r) => Ok(Value::Bool(self.eval_value(l, ctx)?.as_int() > self.eval_value(r, ctx)?.as_int())),
            Condition::Ge(l, r) => Ok(Value::Bool(self.eval_value(l, ctx)?.as_int() >= self.eval_value(r, ctx)?.as_int())),
            Condition::Add(l, r) => Ok(Value::Int(self.eval_value(l, ctx)?.as_int().wrapping_add(self.eval_value(r, ctx)?.as_int()))),
            Condition::Sub(l, r) => Ok(Value::Int(self.eval_value(l, ctx)?.as_int().wrapping_sub(self.eval_value(r, ctx)?.as_int()))),
            Condition::Mul(l, r) => Ok(Value::Int(self.eval_value(l, ctx)?.as_int().wrapping_mul(self.eval_value(r, ctx)?.as_int()))),
            Condition::Div(l, r) => {
                let (a, b) = (self.eval_value(l, ctx)?.as_int(), self.eval_value(r, ctx)?.as_int());
                if b == 0 { return Err(YaraError::TypeError("division by zero".into())); }
                Ok(Value::Int(a / b))
            }
            Condition::Mod(l, r) => {
                let (a, b) = (self.eval_value(l, ctx)?.as_int(), self.eval_value(r, ctx)?.as_int());
                if b == 0 { return Err(YaraError::TypeError("modulo by zero".into())); }
                Ok(Value::Int(a % b))
            }
            _ => self.eval_value_extended(cond, ctx),
        }
    }

    fn eval_value_extended(&self, cond: &Condition, ctx: &EvalContext<'_>) -> Result<Value, YaraError> {
        match cond {
            Condition::StringRef(ident) => {
                ident.strip_prefix('#').map_or_else(|| {
                    let matched = ctx.matches.get(ident).is_some_and(StringMatches::matched);
                    Ok(Value::Bool(matched))
                }, |stripped| {
                    let real = format!("${stripped}");
                    let count = i64::try_from(ctx.matches.get(&real).map_or(0, StringMatches::count)).unwrap_or(i64::MAX);
                    Ok(Value::Int(count))
                })
            }
            Condition::StringWildcard(prefix) => {
                let matched = ctx.matches.iter().any(|(k, v)| k.starts_with(prefix) && v.matched());
                Ok(Value::Bool(matched))
            }
            Condition::Of { count, set } => {
                let target_count = self.eval_value(count, ctx)?.as_int();
                let string_ids = Self::resolve_set(set, ctx);
                let match_count = i64::try_from(string_ids.iter()
                    .filter(|id| ctx.matches.get(*id).is_some_and(StringMatches::matched))
                    .count()).unwrap_or(i64::MAX);
                let total = i64::try_from(string_ids.len()).unwrap_or(i64::MAX);
                let result = if target_count == -1 { match_count == total }
                    else if target_count == 0 { match_count == 0 }
                    else { match_count >= target_count };
                Ok(Value::Bool(result))
            }
            Condition::At(string_ref, offset_expr) => {
                let offset_raw = self.eval_value(offset_expr, ctx)?.as_int();
                if offset_raw < 0 { return Ok(Value::Bool(false)); }
                let offset = usize::try_from(offset_raw).unwrap_or(0);
                let matched = matches!(string_ref.as_ref(), Condition::StringRef(ident)
                    if ctx.matches.get(ident).is_some_and(|m| m.at_offset(offset)));
                Ok(Value::Bool(matched))
            }
            Condition::In(string_ref, lo_expr, hi_expr) => {
                let lo_raw = self.eval_value(lo_expr, ctx)?.as_int();
                let hi_raw = self.eval_value(hi_expr, ctx)?.as_int();
                let lo = if lo_raw < 0 { 0usize } else { usize::try_from(lo_raw).unwrap_or(0) };
                if hi_raw < 0 { return Ok(Value::Bool(false)); }
                let hi = usize::try_from(hi_raw).unwrap_or(0);
                let matched = matches!(string_ref.as_ref(), Condition::StringRef(ident)
                    if ctx.matches.get(ident).is_some_and(|m| m.in_range(lo, hi)));
                Ok(Value::Bool(matched))
            }
            Condition::Matches(expr, regex_str) => {
                let Value::Str(content) = self.eval_value(expr, ctx)? else { return Ok(Value::Bool(false)) };
                Ok(Value::Bool(content.contains(regex_str.as_str())))
            }
            Condition::For { count, set, body } => {
                let target_count = self.eval_value(count, ctx)?.as_int();
                let ids = Self::resolve_set(set, ctx);
                let match_count: i64 = ids.iter().map(|id| {
                    let has_hits = ctx.matches.get(id).is_some_and(StringMatches::matched);
                    let body_str = self.eval_value(body, ctx).map(|v| v.as_str().to_string()).unwrap_or_default();
                    let body_ok = self.eval(body, ctx).unwrap_or(false);
                    i64::from(body_ok && (has_hits || body_str.contains(id.as_str())))
                }).sum();
                Ok(Value::Bool(match_count >= target_count))
            }
            Condition::ModuleField(module, field) => {
                let key = (module.clone(), field.clone());
                if let Some(&v) = ctx.module_ints.get(&key) { return Ok(Value::Int(v)); }
                if let Some(v) = ctx.module_strs.get(&key) { return Ok(Value::Str(v.clone())); }
                if let Some(&b) = ctx.module_bools.get(&key) { return Ok(Value::Bool(b)); }
                if module == "pe" || module == "elf" { return Ok(Value::Int(0)); }
                Ok(Value::Undef)
            }
            Condition::ModuleCall(module, field, _args) => {
                let key = (module.clone(), field.clone());
                if let Some(&v) = ctx.module_ints.get(&key) { return Ok(Value::Int(v)); }
                Ok(Value::Int(0))
            }
            Condition::Defined(inner) => Ok(Value::Bool(!matches!(self.eval_value(inner, ctx)?, Value::Undef))),
            _ => Ok(Value::Undef),
        }
    }

    fn resolve_set(set: &StringSet, ctx: &EvalContext<'_>) -> Vec<String> {
        match set {
            StringSet::Them => ctx.matches.keys().cloned().collect(),
            StringSet::List(ids) => ids.clone(),
            StringSet::Wildcard(prefix) => ctx
                .matches
                .keys()
                .filter(|k| k.starts_with(prefix.as_str()))
                .cloned()
                .collect(),
        }
    }
}

impl Default for ConditionEval {
    fn default() -> Self {
        Self::new()
    }
}

// ─── StringMatcher ────────────────────────────────────────────────────────────

/// Scans file bytes for all pattern matches defined in a rule.
pub struct StringMatcher;

impl StringMatcher {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Scan file data for all strings in `rule`, populating the context.
    pub fn scan_strings<'a>(&self, rule: &YaraRule, file: &'a [u8], ctx: &mut EvalContext<'a>) {
        for s in &rule.strings {
            // Always register the identifier so set resolution ("of them") sees
            // every declared string, even those with no matches.
            let entry = ctx.matches.entry(s.identifier.clone()).or_default();
            let locations = Self::find_string(s, file);
            entry.locations.extend(locations);
        }
    }

    fn find_string(s: &YaraString, file: &[u8]) -> Vec<MatchLocation> {
        match &s.kind {
            YaraStringKind::Text(text) => Self::match_text(text, file, s.modifiers.encoding.nocase, s.modifiers.encoding.wide),
            YaraStringKind::Hex(pattern) => Self::match_hex(pattern, file),
            YaraStringKind::Regex(pat, flags) => Self::match_regex(pat, file, flags.contains('i')),
        }
    }

    fn match_text(text: &str, file: &[u8], nocase: bool, wide: bool) -> Vec<MatchLocation> {
        let mut locs = Vec::new();
        let needle = text.as_bytes();
        if nocase {
            let lower_file: Vec<u8> = file.iter().map(u8::to_ascii_lowercase).collect();
            let lower_needle: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
            let mut start = 0;
            while start + lower_needle.len() <= lower_file.len() {
                if lower_file[start..].starts_with(&lower_needle) {
                    locs.push(MatchLocation { offset: start, length: needle.len() });
                }
                start += 1;
            }
        } else {
            let mut start = 0;
            while start + needle.len() <= file.len() {
                if file[start..].starts_with(needle) {
                    locs.push(MatchLocation { offset: start, length: needle.len() });
                }
                start += 1;
            }
        }
        if wide {
            let wide_bytes: Vec<u8> = needle.iter().flat_map(|&b| [b, 0]).collect();
            let mut start = 0;
            while start + wide_bytes.len() <= file.len() {
                if file[start..].starts_with(&wide_bytes) {
                    locs.push(MatchLocation { offset: start, length: wide_bytes.len() });
                }
                start += 1;
            }
        }
        locs
    }

    fn match_hex(pattern: &[HexByte], file: &[u8]) -> Vec<MatchLocation> {
        let mut locs = Vec::new();
        if pattern.is_empty() { return locs; }
        let pat_len = pattern.len();
        for start in 0..file.len() {
            if start + pat_len > file.len() { break; }
            let matched = pattern.iter().enumerate().all(|(i, hp)| match hp {
                HexByte::Fixed(b) => file[start + i] == *b,
                HexByte::Wildcard | HexByte::Jump(_, _) => true,
                HexByte::NibbleHi(hi) => file[start + i] >> 4 == *hi,
                HexByte::NibbleLo(lo) => file[start + i] & 0x0F == *lo,
            });
            if matched { locs.push(MatchLocation { offset: start, length: pat_len }); }
        }
        locs
    }

    fn match_regex(pat: &str, file: &[u8], nocase: bool) -> Vec<MatchLocation> {
        let needle = pat.as_bytes();
        let mut locs = Vec::new();
        if nocase {
            let lower: Vec<u8> = file.iter().map(u8::to_ascii_lowercase).collect();
            let lower_needle: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
            let mut start = 0;
            while start + lower_needle.len() <= lower.len() {
                if lower[start..].starts_with(&lower_needle) {
                    locs.push(MatchLocation { offset: start, length: needle.len() });
                }
                start += 1;
            }
        } else {
            let mut start = 0;
            while start + needle.len() <= file.len() {
                if file[start..].starts_with(needle) {
                    locs.push(MatchLocation { offset: start, length: needle.len() });
                }
                start += 1;
            }
        }
        locs
    }
}

impl Default for StringMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RuleEvaluator ────────────────────────────────────────────────────────────

/// Scan file bytes against a full [`YaraRule`].
pub struct RuleEvaluator {
    eval: ConditionEval,
    matcher: StringMatcher,
}

impl RuleEvaluator {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            eval: ConditionEval::new(),
            matcher: StringMatcher::new(),
        }
    }

    /// Returns true if `file` matches `rule`.
    ///
    /// # Errors
    ///
    /// Returns a [`YaraError`] if condition evaluation fails.
    pub fn matches(&self, rule: &YaraRule, file: &[u8]) -> Result<bool, YaraError> {
        let mut ctx = EvalContext::new(file);
        self.matcher.scan_strings(rule, file, &mut ctx);
        self.eval.eval(&rule.condition, &ctx)
    }

    /// Returns true with a pre-populated context (caller handles string scanning).
    ///
    /// # Errors
    ///
    /// Returns a [`YaraError`] if condition evaluation fails.
    pub fn matches_with_ctx(
        &self,
        rule: &YaraRule,
        ctx: &EvalContext<'_>,
    ) -> Result<bool, YaraError> {
        self.eval.eval(&rule.condition, ctx)
    }
}

impl Default for RuleEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_parser::{Condition, parse_rule};

    fn eval_rule(src: &str, file: &[u8]) -> bool {
        let rule = parse_rule(src).unwrap();
        let ev = RuleEvaluator::new();
        ev.matches(&rule, file).unwrap()
    }

    #[test]
    fn test_true_rule() {
        assert!(eval_rule("rule r { condition: true }", b"data"));
    }

    #[test]
    fn test_false_rule() {
        assert!(!eval_rule("rule r { condition: false }", b"data"));
    }

    #[test]
    fn test_filesize_gt() {
        assert!(eval_rule("rule r { condition: filesize > 3 }", b"hello"));
        assert!(!eval_rule("rule r { condition: filesize > 10 }", b"hi"));
    }

    #[test]
    fn test_filesize_eq() {
        assert!(eval_rule("rule r { condition: filesize == 5 }", b"hello"));
    }

    #[test]
    fn test_filesize_le() {
        assert!(eval_rule("rule r { condition: filesize <= 5 }", b"hello"));
    }

    #[test]
    fn test_not_true() {
        assert!(!eval_rule("rule r { condition: not true }", b"x"));
    }

    #[test]
    fn test_and_both_true() {
        assert!(eval_rule("rule r { condition: true and true }", b"x"));
    }

    #[test]
    fn test_and_one_false() {
        assert!(!eval_rule("rule r { condition: true and false }", b"x"));
    }

    #[test]
    fn test_or_one_true() {
        assert!(eval_rule("rule r { condition: false or true }", b"x"));
    }

    #[test]
    fn test_or_both_false() {
        assert!(!eval_rule("rule r { condition: false or false }", b"x"));
    }

    #[test]
    fn test_string_match() {
        assert!(eval_rule(
            r#"rule r { strings: $a = "hello" condition: $a }"#,
            b"say hello world"
        ));
    }

    #[test]
    fn test_string_no_match() {
        assert!(!eval_rule(
            r#"rule r { strings: $a = "xyz" condition: $a }"#,
            b"hello world"
        ));
    }

    #[test]
    fn test_string_nocase() {
        assert!(eval_rule(
            r#"rule r { strings: $a = "HELLO" nocase condition: $a }"#,
            b"say hello world"
        ));
    }

    #[test]
    fn test_any_of_them() {
        assert!(eval_rule(
            r#"rule r { strings: $a = "foo" $b = "bar" condition: any of them }"#,
            b"contains foo stuff"
        ));
    }

    #[test]
    fn test_all_of_them_pass() {
        assert!(eval_rule(
            r#"rule r { strings: $a = "foo" $b = "bar" condition: all of them }"#,
            b"foo and bar"
        ));
    }

    #[test]
    fn test_all_of_them_fail() {
        assert!(!eval_rule(
            r#"rule r { strings: $a = "foo" $b = "bar" condition: all of them }"#,
            b"only foo"
        ));
    }

    #[test]
    fn test_eval_add() {
        let rule = parse_rule("rule r { condition: 2 + 3 == 5 }").unwrap();
        let ev = RuleEvaluator::new();
        assert!(ev.matches(&rule, b"x").unwrap());
    }

    #[test]
    fn test_eval_sub() {
        let rule = parse_rule("rule r { condition: 10 - 3 == 7 }").unwrap();
        let ev = RuleEvaluator::new();
        assert!(ev.matches(&rule, b"x").unwrap());
    }

    #[test]
    fn test_eval_ne() {
        let rule = parse_rule("rule r { condition: 5 != 3 }").unwrap();
        let ev = RuleEvaluator::new();
        assert!(ev.matches(&rule, b"x").unwrap());
    }

    #[test]
    fn test_eval_lt_pass() {
        let rule = parse_rule("rule r { condition: 3 < 5 }").unwrap();
        let ev = RuleEvaluator::new();
        assert!(ev.matches(&rule, b"x").unwrap());
    }

    #[test]
    fn test_eval_lt_fail() {
        let rule = parse_rule("rule r { condition: 5 < 3 }").unwrap();
        let ev = RuleEvaluator::new();
        assert!(!ev.matches(&rule, b"x").unwrap());
    }

    #[test]
    fn test_string_at_offset() {
        let eval = ConditionEval::new();
        let file = b"xxhelloxx";
        let mut ctx = EvalContext::new(file);
        ctx.add_match("$a", 2, 5);
        let cond = Condition::At(
            Box::new(Condition::StringRef("$a".into())),
            Box::new(Condition::Int(2)),
        );
        assert!(eval.eval(&cond, &ctx).unwrap());
    }

    #[test]
    fn test_string_in_range() {
        let eval = ConditionEval::new();
        let file = b"xxhelloxx";
        let mut ctx = EvalContext::new(file);
        ctx.add_match("$a", 2, 5);
        let cond = Condition::In(
            Box::new(Condition::StringRef("$a".into())),
            Box::new(Condition::Int(0)),
            Box::new(Condition::Int(5)),
        );
        assert!(eval.eval(&cond, &ctx).unwrap());
    }

    #[test]
    fn test_module_field_pe_default_zero() {
        let eval = ConditionEval::new();
        let file = b"data";
        let ctx = EvalContext::new(file);
        let cond = Condition::ModuleField("pe".into(), "entry_point".into());
        let val = eval.eval(&cond, &ctx).unwrap();
        // Default 0 → false
        assert!(!val);
    }

    #[test]
    fn test_module_field_custom() {
        let eval = ConditionEval::new();
        let file = b"data";
        let mut ctx = EvalContext::new(file);
        ctx.module_ints
            .insert(("pe".into(), "entry_point".into()), 0x1000);
        let cond = Condition::Gt(
            Box::new(Condition::ModuleField("pe".into(), "entry_point".into())),
            Box::new(Condition::Int(0)),
        );
        assert!(eval.eval(&cond, &ctx).unwrap());
    }

    #[test]
    fn test_hex_pattern_match() {
        use crate::rule_parser::HexByte;
        let sm = StringMatcher::new();
        let file = b"\x60\xE8\xAA\xBB\x00\x00";
        let s = crate::rule_parser::YaraString::new(
            "$a".into(),
            YaraStringKind::Hex(vec![
                HexByte::Fixed(0x60),
                HexByte::Fixed(0xE8),
                HexByte::Wildcard,
                HexByte::Wildcard,
            ]),
            Default::default(),
        );
        let locs = StringMatcher::find_string(&s, file);
        assert!(!locs.is_empty());
    }

    #[test]
    fn test_filesize_arithmetic() {
        let rule = parse_rule("rule r { condition: filesize + 1 > 5 }").unwrap();
        let ev = RuleEvaluator::new();
        assert!(ev.matches(&rule, b"hello").unwrap()); // filesize=5, 5+1=6>5
    }

    #[test]
    fn test_entrypoint_with_context() {
        let eval = ConditionEval::new();
        let file = b"data";
        let ctx = EvalContext::new(file).with_entrypoint(0x400);
        let cond = Condition::Eq(
            Box::new(Condition::Entrypoint),
            Box::new(Condition::Int(0x400)),
        );
        assert!(eval.eval(&cond, &ctx).unwrap());
    }
}
