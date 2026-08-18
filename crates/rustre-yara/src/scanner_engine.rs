// scanner_engine.rs — Multi-threaded YARA scanning engine

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

use crate::rule_compiler::{CompiledPattern, CompiledPatternKind, CompiledRule, CompiledRuleSet, HexToken, PatternModifiers};

// ── Match types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, serde_json::Value>,
    pub pattern_matches: Vec<PatternMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub offsets: Vec<MatchOffset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchOffset {
    pub offset: u64,
    pub length: usize,
    pub data_preview: Vec<u8>,
    pub xor_key: Option<u8>,
}

// ── Scan context ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub file_size: u64,
    pub entry_point: Option<u64>,
    pub base_address: u64,
    pub max_matches_per_pattern: usize,
    pub timeout: Duration,
    pub scan_flags: ScanFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ScanFlags: u32 {
        const REPORT_RULES_MATCHING = 0x01;
        const REPORT_RULES_NOT_MATCHING = 0x02;
        const FAST_MODE = 0x04;
        const NO_TRYCATCH = 0x08;
        const PROCESS_MEMORY = 0x10;
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            file_size: 0,
            entry_point: None,
            base_address: 0,
            max_matches_per_pattern: 1_000,
            timeout: Duration::from_mins(1),
            scan_flags: ScanFlags::REPORT_RULES_MATCHING,
        }
    }
}

// ── Scanner engine ─────────────────────────────────────────────────────────────

pub struct ScannerEngine {
    rule_set: Arc<CompiledRuleSet>,
    aho_corasick: Arc<aho_corasick::AhoCorasick>,
    atom_to_patterns: Vec<(usize, usize)>,  // (rule_idx, pattern_idx)
}

impl ScannerEngine {
    /// # Errors
    ///
    /// Returns an error if the Aho-Corasick automaton cannot be built.
    pub fn new(rule_set: Arc<CompiledRuleSet>) -> Result<Self> {
        let (ac, mapping) = Self::build_aho_corasick(&rule_set)?;
        Ok(Self {
            rule_set,
            aho_corasick: Arc::new(ac),
            atom_to_patterns: mapping,
        })
    }

    fn build_aho_corasick(
        rule_set: &CompiledRuleSet,
    ) -> Result<(aho_corasick::AhoCorasick, Vec<(usize, usize)>)> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut mapping: Vec<(usize, usize)> = Vec::new();

        for (rule_idx, rule) in rule_set.all_rules().enumerate() {
            for (pat_idx, pat) in rule.patterns.iter().enumerate() {
                for atom in &pat.compiled_atoms {
                    if atom.bytes.len() >= 2 {
                        patterns.push(atom.bytes.clone());
                        mapping.push((rule_idx, pat_idx));
                    }
                }
            }
        }

        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            .build(&patterns)
            .context("Failed to build Aho-Corasick")?;

        Ok((ac, mapping))
    }

    /// # Errors
    ///
    /// Returns an error if scanning fails.
    pub fn scan_bytes(&self, data: &[u8], ctx: &ScanContext) -> Result<Vec<ScanMatch>> {
        let start = Instant::now();
        let mut results = Vec::new();

        // Collect candidate rules via Aho-Corasick pre-filter
        let mut candidate_rules: std::collections::HashSet<usize> =
            std::collections::HashSet::new();

        for mat in self.aho_corasick.find_iter(data) {
            if start.elapsed() > ctx.timeout {
                break;
            }
            let (rule_idx, _pat_idx) = self.atom_to_patterns[mat.pattern().as_usize()];
            candidate_rules.insert(rule_idx);
        }

        let rules: Vec<(usize, &CompiledRule)> = self
            .rule_set
            .all_rules()
            .enumerate()
            .filter(|(i, _)| candidate_rules.contains(i))
            .collect();

        // Full match for each candidate rule
        for (_, rule) in &rules {
            if start.elapsed() > ctx.timeout {
                break;
            }

            let mut pattern_matches: Vec<PatternMatch> = Vec::new();
            let mut all_matched = true;

            for pat in &rule.patterns {
                let matches = Self::match_pattern(data, pat, ctx);
                if matches.is_empty() && !pat.modifiers.output.private {
                    all_matched = false;
                }
                if !matches.is_empty() {
                    pattern_matches.push(PatternMatch {
                        pattern_id: pat.id.clone(),
                        offsets: matches,
                    });
                }
            }

            // Fast-path: if every non-private pattern matched, and the rule
            // has no explicit condition bytecode beyond the implicit
            // "all-of-them", we can skip the VM entirely.
            if all_matched && rule.condition_bytecode.is_empty() {
                let mut meta = HashMap::new();
                for (k, v) in &rule.metadata {
                    use crate::rule_compiler::MetaValue;
                    let jv = match v {
                        MetaValue::String(s) => serde_json::Value::String(s.clone()),
                        MetaValue::Integer(i) => serde_json::Value::Number((*i).into()),
                        MetaValue::Boolean(b) => serde_json::Value::Bool(*b),
                    };
                    meta.insert(k.clone(), jv);
                }
                results.push(ScanMatch {
                    rule_name: rule.name.clone(),
                    namespace: rule.namespace.clone(),
                    tags: rule.tags.clone(),
                    meta,
                    pattern_matches,
                });
                continue;
            }

            // Evaluate condition bytecode
            let condition_result =
                Self::eval_condition(data, &rule.condition_bytecode, &pattern_matches, ctx)?;

            if condition_result {
                let mut meta = HashMap::new();
                for (k, v) in &rule.metadata {
                    use crate::rule_compiler::MetaValue;
                    let jv = match v {
                        MetaValue::String(s) => serde_json::Value::String(s.clone()),
                        MetaValue::Integer(i) => serde_json::Value::Number((*i).into()),
                        MetaValue::Boolean(b) => serde_json::Value::Bool(*b),
                    };
                    meta.insert(k.clone(), jv);
                }

                results.push(ScanMatch {
                    rule_name: rule.name.clone(),
                    namespace: rule.namespace.clone(),
                    tags: rule.tags.clone(),
                    meta,
                    pattern_matches,
                });

                // FAST_MODE: exit after the first matching rule
                if ctx.scan_flags.contains(ScanFlags::FAST_MODE) {
                    return Ok(results);
                }
            }
        }

        Ok(results)
    }

    /// # Errors
    ///
    /// Returns an error if scanning fails.
    pub fn scan_bytes_parallel(
        &self,
        data: &[u8],
        ctx: &ScanContext,
    ) -> Result<Vec<ScanMatch>> {
        // For large files, split into chunks and scan in parallel
        if data.len() < 1_000_000 {
            return self.scan_bytes(data, ctx);
        }

        let chunk_size = 512 * 1024;
        let overlap = 4096; // overlap to catch matches spanning chunk boundaries

        let results: Vec<_> = data
            .par_chunks(chunk_size)
            .enumerate()
            .flat_map_iter(|(i, chunk)| {
                let offset = i * chunk_size;
                let extended_end = (offset + chunk_size + overlap).min(data.len());
                let extended_chunk = &data[offset..extended_end];
                // Empty base chunk means nothing new to scan in this slot;
                // returning an empty Vec short-circuits the scan call.
                let raw: Vec<ScanMatch> = if chunk.is_empty() {
                    Vec::new()
                } else {
                    // Errors in parallel chunks are silently dropped to allow
                    // partial results; callers should use scan_bytes for strict error handling.
                    self.scan_bytes(extended_chunk, ctx).unwrap_or_default()
                };
                raw.into_iter().map(move |mut m| {
                    for pm in &mut m.pattern_matches {
                        for mo in &mut pm.offsets {
                            mo.offset += offset as u64;
                        }
                    }
                    m
                })
            })
            .collect();

        // Deduplicate by rule name + sorted set of all (pattern_id, offset) pairs.
        // Using only the first offset caused false duplicates when the same real match
        // straddled a chunk boundary and was seen with different first-pattern offsets.
        let mut seen: std::collections::HashSet<(String, Vec<(String, u64)>)> =
            std::collections::HashSet::new();
        let mut deduped = Vec::new();
        for m in results {
            let mut key_offsets: Vec<(String, u64)> = m
                .pattern_matches
                .iter()
                .flat_map(|pm| {
                    pm.offsets
                        .iter()
                        .map(|mo| (pm.pattern_id.clone(), mo.offset))
                })
                .collect();
            key_offsets.sort_unstable();
            let key = (m.rule_name.clone(), key_offsets);
            if seen.insert(key) {
                deduped.push(m);
            }
        }
        Ok(deduped)
    }

    fn match_pattern(
        data: &[u8],
        pat: &CompiledPattern,
        ctx: &ScanContext,
    ) -> Vec<MatchOffset> {
        let mut matches = Vec::new();

        match &pat.kind {
            CompiledPatternKind::ByteString(needle) => {
                matches.extend(Self::match_bytes(data, needle, &pat.modifiers, ctx));
            }
            CompiledPatternKind::HexString(tokens) => {
                matches.extend(Self::match_hex(data, tokens, &pat.modifiers, ctx));
            }
            CompiledPatternKind::Regex(re_str) => {
                let flags = if pat.modifiers.encoding.nocase { "(?i)" } else { "" };
                let full_re = format!("{flags}{re_str}");
                if let Ok(re) = regex::bytes::Regex::new(&full_re) {
                    for m in re.find_iter(data) {
                        if matches.len() >= ctx.max_matches_per_pattern {
                            break;
                        }
                        matches.push(MatchOffset {
                            offset: m.start() as u64 + ctx.base_address,
                            length: m.len(),
                            data_preview: m.as_bytes()[..m.len().min(16)].to_vec(),
                            xor_key: None,
                        });
                    }
                }
            }
        }

        matches
    }

    fn match_bytes(
        data: &[u8],
        needle: &[u8],
        mods: &PatternModifiers,
        ctx: &ScanContext,
    ) -> Vec<MatchOffset> {
        let mut results = Vec::new();

        // Handle XOR modifier
        if let Some((xor_min, xor_max)) = mods.xor {
            for key in xor_min..=xor_max {
                let xored: Vec<u8> = needle.iter().map(|&b| b ^ key).collect();
                for offset in find_pattern(data, &xored, mods.output.fullword) {
                    if results.len() >= ctx.max_matches_per_pattern {
                        return results;
                    }
                    results.push(MatchOffset {
                        offset: offset as u64 + ctx.base_address,
                        length: xored.len(),
                        data_preview: data[offset..offset + xored.len().min(16)].to_vec(),
                        xor_key: Some(key),
                    });
                }
            }
            return results;
        }

        // Normal byte string match
        if mods.encoding.ascii || (!mods.encoding.wide) {
            let search_needle: Vec<u8> = if mods.encoding.nocase {
                needle.iter().map(u8::to_ascii_lowercase).collect()
            } else {
                needle.to_vec()
            };

            let haystack: Vec<u8> = if mods.encoding.nocase {
                data.iter().map(u8::to_ascii_lowercase).collect()
            } else {
                data.to_vec()
            };

            for offset in find_pattern(&haystack, &search_needle, mods.output.fullword) {
                if results.len() >= ctx.max_matches_per_pattern {
                    return results;
                }
                let end = (offset + needle.len()).min(data.len());
                results.push(MatchOffset {
                    offset: offset as u64 + ctx.base_address,
                    length: needle.len(),
                    data_preview: data[offset..end.min(offset + 16)].to_vec(),
                    xor_key: None,
                });
            }
        }

        // Wide string match
        if mods.encoding.wide {
            let wide: Vec<u8> = needle.iter().flat_map(|&b| [b, 0u8]).collect();
            let search_wide: Vec<u8> = if mods.encoding.nocase {
                wide.iter().map(u8::to_ascii_lowercase).collect()
            } else {
                wide.clone()
            };

            let haystack: Vec<u8> = if mods.encoding.nocase {
                data.iter().map(u8::to_ascii_lowercase).collect()
            } else {
                data.to_vec()
            };

            for offset in find_pattern(&haystack, &search_wide, false) {
                if results.len() >= ctx.max_matches_per_pattern {
                    return results;
                }
                let end = (offset + wide.len()).min(data.len());
                results.push(MatchOffset {
                    offset: offset as u64 + ctx.base_address,
                    length: wide.len(),
                    data_preview: data[offset..end.min(offset + 16)].to_vec(),
                    xor_key: None,
                });
            }
        }

        results
    }

    fn match_hex(
        data: &[u8],
        tokens: &[HexToken],
        mods: &PatternModifiers,
        ctx: &ScanContext,
    ) -> Vec<MatchOffset> {
        let mut results = Vec::new();

        // Private patterns produce match information for condition evaluation
        // but should not be persisted past the scanner: cap their result count
        // to the minimum (1) so we know "matched / not matched" without
        // collecting full offsets.
        let result_cap = if mods.output.private {
            1
        } else {
            ctx.max_matches_per_pattern
        };

        for start in 0..data.len() {
            if results.len() >= result_cap {
                break;
            }
            let matcher = HexMatcher::new(tokens, data, start);
            if let Some(end) = matcher.try_match() {
                let length = end - start;
                results.push(MatchOffset {
                    offset: start as u64 + ctx.base_address,
                    length,
                    data_preview: data[start..end.min(start + 16)].to_vec(),
                    xor_key: None,
                });
            }
        }

        results
    }

    fn eval_arith_cmp_bool_op(op: &crate::rule_compiler::ConditionOp, stack: &mut Vec<CondValue>) {
        use crate::rule_compiler::ConditionOp;
        match op {
            ConditionOp::And => { let b = stack.pop().and_then(|v| v.as_bool()).unwrap_or(false); let a = stack.pop().and_then(|v| v.as_bool()).unwrap_or(false); stack.push(CondValue::Bool(a && b)); }
            ConditionOp::Or  => { let b = stack.pop().and_then(|v| v.as_bool()).unwrap_or(false); let a = stack.pop().and_then(|v| v.as_bool()).unwrap_or(false); stack.push(CondValue::Bool(a || b)); }
            ConditionOp::Not => { let a = stack.pop().and_then(|v| v.as_bool()).unwrap_or(false); stack.push(CondValue::Bool(!a)); }
            ConditionOp::Eq  => { let b = stack.pop(); let a = stack.pop(); stack.push(CondValue::Bool(a == b)); }
            ConditionOp::Ne  => { let b = stack.pop(); let a = stack.pop(); stack.push(CondValue::Bool(a != b)); }
            ConditionOp::Lt  => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Bool(a < b)); }
            ConditionOp::Le  => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Bool(a <= b)); }
            ConditionOp::Gt  => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Bool(a > b)); }
            ConditionOp::Ge  => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Bool(a >= b)); }
            ConditionOp::Add => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Int(a.wrapping_add(b))); }
            ConditionOp::Sub => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Int(a.wrapping_sub(b))); }
            ConditionOp::Mul => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Int(a.wrapping_mul(b))); }
            ConditionOp::Div => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(1); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Int(if b != 0 { a / b } else { 0 })); }
            ConditionOp::Mod => { let b = stack.pop().and_then(|v| v.as_int()).unwrap_or(1); let a = stack.pop().and_then(|v| v.as_int()).unwrap_or(0); stack.push(CondValue::Int(if b != 0 { a % b } else { 0 })); }
            _ => {}
        }
    }

    fn eval_condition(
        data: &[u8],
        bytecode: &[crate::rule_compiler::ConditionOp],
        pattern_matches: &[PatternMatch],
        ctx: &ScanContext,
    ) -> Result<bool> {
        use crate::rule_compiler::ConditionOp;

        let mut stack: Vec<CondValue> = Vec::with_capacity(32);
        let mut ip = 0usize;

        let pattern_match_map: HashMap<&str, &PatternMatch> = pattern_matches
            .iter()
            .map(|pm| (pm.pattern_id.as_str(), pm))
            .collect();

        while ip < bytecode.len() {
            match &bytecode[ip] {
                ConditionOp::PushBool(b)   => stack.push(CondValue::Bool(*b)),
                ConditionOp::PushInt(i)    => stack.push(CondValue::Int(*i)),
                ConditionOp::PushFloat(f)  => stack.push(CondValue::Float(*f)),
                ConditionOp::PushString(s) => stack.push(CondValue::Str(s.clone())),
                ConditionOp::FileSize => {
                    let size = if ctx.file_size == 0 { i64::try_from(data.len()).unwrap_or(i64::MAX) } else { i64::try_from(ctx.file_size).unwrap_or(i64::MAX) };
                    stack.push(CondValue::Int(size));
                }
                ConditionOp::EntryPoint => stack.push(CondValue::Int(
                    ctx.entry_point.map_or(-1, |e| i64::try_from(e).unwrap_or(i64::MAX)),
                )),
                ConditionOp::PatternMatch(id) => {
                    stack.push(CondValue::Bool(pattern_match_map.contains_key(id.as_str())));
                }
                ConditionOp::PatternCount(id) => {
                    match pattern_match_map.get(id.as_str()) {
                        Some(pm) => stack.push(CondValue::Int(i64::try_from(pm.offsets.len()).unwrap_or(i64::MAX))),
                        None     => stack.push(CondValue::Undef),
                    }
                }
                op @ (ConditionOp::And | ConditionOp::Or | ConditionOp::Not |
                       ConditionOp::Eq | ConditionOp::Ne |
                       ConditionOp::Lt | ConditionOp::Le | ConditionOp::Gt | ConditionOp::Ge |
                       ConditionOp::Add | ConditionOp::Sub | ConditionOp::Mul | ConditionOp::Div | ConditionOp::Mod) => {
                    Self::eval_arith_cmp_bool_op(op, &mut stack);
                }
                op @ (ConditionOp::Contains | ConditionOp::IContains | ConditionOp::StartsWith | ConditionOp::EndsWith | ConditionOp::Matches) => {
                    Self::eval_string_op(op, &mut stack);
                }
                ConditionOp::Of { set } => {
                    use crate::rule_compiler::OfSet;
                    let result = match set {
                        OfSet::All         => pattern_match_map.len() == pattern_matches.len(),
                        OfSet::Any         => !pattern_match_map.is_empty(),
                        OfSet::N(n)        => pattern_match_map.len() >= usize::from(*n),
                        OfSet::Patterns(ids) => ids.iter().all(|id| pattern_match_map.contains_key(id.as_str())),
                    };
                    stack.push(CondValue::Bool(result));
                }
                ConditionOp::Jump(delta) => {
                    let new_ip = i64::try_from(ip).unwrap_or(i64::MAX).wrapping_add(i64::from(*delta));
                    if new_ip < 0 || usize::try_from(new_ip).unwrap_or(usize::MAX) > bytecode.len() {
                        return Err(anyhow::anyhow!("bytecode jump out of bounds: ip={ip} delta={delta}"));
                    }
                    ip = usize::try_from(new_ip).unwrap_or(0);
                    continue;
                }
                ConditionOp::JumpIfFalse(delta) => {
                    if !stack.last().and_then(CondValue::as_bool).unwrap_or(false) {
                        let new_ip = i64::try_from(ip).unwrap_or(i64::MAX).wrapping_add(i64::from(*delta));
                        if new_ip < 0 || usize::try_from(new_ip).unwrap_or(usize::MAX) > bytecode.len() {
                            return Err(anyhow::anyhow!("bytecode jump out of bounds: ip={ip} delta={delta}"));
                        }
                        ip = usize::try_from(new_ip).unwrap_or(0);
                        continue;
                    }
                }
                ConditionOp::JumpIfTrue(delta)
                    if stack.last().and_then(CondValue::as_bool).unwrap_or(false) => {
                        let new_ip = i64::try_from(ip).unwrap_or(i64::MAX).wrapping_add(i64::from(*delta));
                        if new_ip < 0 || usize::try_from(new_ip).unwrap_or(usize::MAX) > bytecode.len() {
                            return Err(anyhow::anyhow!("bytecode jump out of bounds: ip={ip} delta={delta}"));
                        }
                        ip = usize::try_from(new_ip).unwrap_or(0);
                        continue;
                    }
                _ => {}
            }
            ip += 1;
        }

        Ok(stack.pop().and_then(|v| v.as_bool()).unwrap_or(false))
    }

    fn eval_string_op(op: &crate::rule_compiler::ConditionOp, stack: &mut Vec<CondValue>) {
        use crate::rule_compiler::ConditionOp;
        match op {
            ConditionOp::Contains => {
                let b = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                let a = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                stack.push(CondValue::Bool(a.contains(&b)));
            }
            ConditionOp::IContains => {
                let b = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default().to_lowercase();
                let a = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default().to_lowercase();
                stack.push(CondValue::Bool(a.contains(&b)));
            }
            ConditionOp::StartsWith => {
                let b = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                let a = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                stack.push(CondValue::Bool(a.starts_with(&b)));
            }
            ConditionOp::EndsWith => {
                let b = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                let a = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                stack.push(CondValue::Bool(a.ends_with(&b)));
            }
            ConditionOp::Matches => {
                let re_str = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                let s = stack.pop().and_then(|v| v.as_str_owned()).unwrap_or_default();
                let matched = regex::Regex::new(&re_str)
                    .is_ok_and(|re| re.is_match(&s));
                stack.push(CondValue::Bool(matched));
            }
            _ => {}
        }
    }
}

// ── Condition value ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum CondValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Undef,
}

impl CondValue {
    const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::Int(i) => Some(*i != 0),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    fn as_str_owned(&self) -> Option<String> {
        match self {
            Self::Str(s) => Some(s.clone()),
            _ => None,
        }
    }
}

// ── Hex pattern matcher ────────────────────────────────────────────────────────

struct HexMatcher<'a> {
    tokens: &'a [HexToken],
    data: &'a [u8],
    start: usize,
}

impl<'a> HexMatcher<'a> {
    const fn new(tokens: &'a [HexToken], data: &'a [u8], start: usize) -> Self {
        Self { tokens, data, start }
    }

    fn try_match(&self) -> Option<usize> {
        self.match_tokens(self.tokens, self.start)
    }

    fn match_tokens(&self, tokens: &[HexToken], pos: usize) -> Option<usize> {
        if tokens.is_empty() {
            return Some(pos);
        }
        if pos >= self.data.len() {
            return None;
        }

        match &tokens[0] {
            HexToken::Byte(b) => {
                if self.data[pos] == *b {
                    self.match_tokens(&tokens[1..], pos + 1)
                } else {
                    None
                }
            }
            HexToken::Wildcard => {
                self.match_tokens(&tokens[1..], pos + 1)
            }
            HexToken::Nibble { high, low } => {
                let byte = self.data[pos];
                let high_ok = high.is_none_or(|h| (byte >> 4) == h);
                let low_ok = low.is_none_or(|l| (byte & 0x0F) == l);
                if high_ok && low_ok {
                    self.match_tokens(&tokens[1..], pos + 1)
                } else {
                    None
                }
            }
            HexToken::Jump { min, max } => {
                let min_skip = *min as usize;
                let max_skip = max.unwrap_or(256) as usize;
                for skip in min_skip..=max_skip {
                    if pos + skip > self.data.len() {
                        break;
                    }
                    if let Some(end) = self.match_tokens(&tokens[1..], pos + skip) {
                        return Some(end);
                    }
                }
                None
            }
            HexToken::Alt(alts) => {
                for alt in alts {
                    if let Some(end_of_alt) = self.match_tokens(alt, pos)
                        && let Some(end) = self.match_tokens(&tokens[1..], end_of_alt) {
                            return Some(end);
                        }
                }
                None
            }
        }
    }
}

// ── Utility: find all occurrences of needle in haystack ───────────────────────

fn find_pattern(haystack: &[u8], needle: &[u8], fullword: bool) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return vec![];
    }

    let mut results = Vec::new();
    let mut pos = 0;

    while pos <= haystack.len() - needle.len() {
        if haystack[pos..].starts_with(needle) {
            if fullword {
                let before_ok = pos == 0 || !is_word_char(haystack[pos - 1]);
                let after = pos + needle.len();
                let after_ok = after >= haystack.len() || !is_word_char(haystack[after]);
                if before_ok && after_ok {
                    results.push(pos);
                }
            } else {
                results.push(pos);
            }
            pos += needle.len();
        } else {
            pos += 1;
        }
    }

    results
}

const fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ── Async scanning ─────────────────────────────────────────────────────────────

pub struct AsyncScanner {
    engine: Arc<ScannerEngine>,
}

impl AsyncScanner {
    #[must_use] 
    pub const fn new(engine: Arc<ScannerEngine>) -> Self {
        Self { engine }
    }

    /// # Errors
    ///
    /// Returns an error if the file cannot be read or scanning fails.
    pub async fn scan_file(
        &self,
        path: &std::path::Path,
        ctx: ScanContext,
    ) -> Result<Vec<ScanMatch>> {
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("Cannot read {}", path.display()))?;
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || engine.scan_bytes_parallel(&data, &ctx))
            .await
            .context("Scan task panicked")?
    }

    /// # Errors
    ///
    /// Returns an error if scanning any region fails.
    pub async fn scan_memory_regions(
        &self,
        regions: Vec<(u64, Vec<u8>)>,
        ctx: ScanContext,
    ) -> Result<Vec<ScanMatch>> {
        let mut all = Vec::new();
        for (base, data) in regions {
            let mut region_ctx = ctx.clone();
            region_ctx.base_address = base;
            region_ctx.file_size = u64::try_from(data.len()).unwrap_or(u64::MAX);
            let engine = self.engine.clone();
            let matches =
                tokio::task::spawn_blocking(move || engine.scan_bytes(&data, &region_ctx))
                    .await
                    .context("Scan task panicked")??;
            all.extend(matches);
        }
        Ok(all)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pattern() {
        let haystack = b"hello world hello";
        let needle = b"hello";
        let results = find_pattern(haystack, needle, false);
        assert_eq!(results, vec![0, 12]);
    }

    #[test]
    fn test_find_pattern_fullword() {
        let haystack = b"hello world helloworldhello";
        let needle = b"hello";
        let results = find_pattern(haystack, needle, true);
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn test_hex_matcher_wildcard() {
        let data = b"\x4d\x5a\x00\x01";
        let tokens = vec![
            HexToken::Byte(0x4d),
            HexToken::Byte(0x5a),
            HexToken::Wildcard,
            HexToken::Byte(0x01),
        ];
        let m = HexMatcher::new(&tokens, data, 0);
        assert_eq!(m.try_match(), Some(4));
    }

    #[test]
    fn test_hex_matcher_jump() {
        let data = b"\x4d\x5a\xAA\xBB\xCC\x01";
        let tokens = vec![
            HexToken::Byte(0x4d),
            HexToken::Byte(0x5a),
            HexToken::Jump { min: 1, max: Some(5) },
            HexToken::Byte(0x01),
        ];
        let m = HexMatcher::new(&tokens, data, 0);
        assert_eq!(m.try_match(), Some(6));
    }

    #[test]
    fn test_cond_value_as_bool() {
        assert_eq!(CondValue::Bool(true).as_bool(), Some(true));
        assert_eq!(CondValue::Int(0).as_bool(), Some(false));
        assert_eq!(CondValue::Int(1).as_bool(), Some(true));
    }
}
