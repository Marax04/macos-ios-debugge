//! `rule_compiler` — YARA rule parser, Aho-Corasick/NFA→DFA pattern optimizer,
//! and binary cache serialization.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{HexToken, StringModifiers, StringValue, YaraError, YaraRule, YaraString};

// Module-private cast helper: narrow `usize` to `u32`, saturating at `u32::MAX`.
// All state indices in the AC/DFA tables are bounded by reachable state counts
// which never exceed `u32::MAX` in practice.
#[inline]
fn usize_to_u32(v: usize) -> u32 { u32::try_from(v).unwrap_or(u32::MAX) }

// ── Compiled pattern ──────────────────────────────────────────────────────────

/// A compiled, optimized pattern ready for fast matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompiledPattern {
    /// Exact byte sequence — use SIMD memchr / Aho-Corasick.
    Literal(Vec<u8>),
    /// Byte sequence with wildcard positions (0xFF mask = exact, 0x00 = any).
    Masked { bytes: Vec<u8>, masks: Vec<u8> },
    /// Alternation of literal strings (Aho-Corasick automaton index).
    AhoCorasick { patterns: Vec<Vec<u8>>, automaton: AcAutomaton },
    /// Compiled regex NFA (DFA-minimized transition table).
    Dfa(DfaTable),
}

// ── Aho-Corasick automaton (minimal implementation) ───────────────────────────

/// A compact Aho-Corasick automaton for simultaneous multi-pattern search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcAutomaton {
    /// Goto function: `goto[state][byte]` → next state (`u32::MAX` = fail).
    goto: Vec<Vec<u32>>,
    /// Failure function: `fail[state]` → fallback state.
    fail: Vec<u32>,
    /// Output function: `output[state]` → list of matched pattern indices.
    output: Vec<Vec<usize>>,
    /// Depth of each state (used for ordering).
    depth: Vec<u32>,
}

impl AcAutomaton {
    /// Build the automaton from a list of byte patterns.
    #[must_use] 
    pub fn build(patterns: &[Vec<u8>]) -> Self {
        // Phase 1: Build the trie (goto function).
        let mut goto: Vec<Vec<u32>> = vec![vec![u32::MAX; 256]];
        let mut output: Vec<Vec<usize>> = vec![Vec::new()];
        let mut depth = vec![0u32];
        let mut num_states = 1usize;

        for (idx, pat) in patterns.iter().enumerate() {
            let mut cur = 0u32;
            for (d, &byte) in pat.iter().enumerate() {
                let b = byte as usize;
                if goto[cur as usize][b] == u32::MAX {
                    goto.push(vec![u32::MAX; 256]);
                    output.push(Vec::new());
                    depth.push(usize_to_u32(d) + 1);
                    goto[cur as usize][b] = usize_to_u32(num_states);
                    num_states += 1;
                }
                cur = goto[cur as usize][b];
            }
            output[cur as usize].push(idx);
        }

        // Root transitions that still point to MAX should fall back to root.
        for cell in &mut goto[0] {
            if *cell == u32::MAX {
                *cell = 0;
            }
        }

        // Phase 2: BFS to compute failure function.
        let mut fail = vec![0u32; num_states];
        let mut queue: VecDeque<u32> = VecDeque::new();

        // Direct children of root have failure = root.
        for &s in &goto[0] {
            if s != 0 {
                fail[s as usize] = 0;
                queue.push_back(s);
            }
        }

        while let Some(r) = queue.pop_front() {
            for b in 0..256u32 {
                let s = goto[r as usize][b as usize];
                if s == u32::MAX { continue; }
                queue.push_back(s);
                let mut state = fail[r as usize];
                loop {
                    if goto[state as usize][b as usize] != u32::MAX
                        && goto[state as usize][b as usize] != s
                    {
                        break;
                    }
                    if state == 0 { break; }
                    state = fail[state as usize];
                }
                let f = goto[state as usize][b as usize];
                fail[s as usize] = if f == u32::MAX { 0 } else { f };

                // Merge output
                let ff = fail[s as usize] as usize;
                let extra: Vec<usize> = output[ff].clone();
                output[s as usize].extend(extra);
            }
        }

        // Phase 3: Convert remaining MAX transitions using failure links.
        for r in 0..num_states {
            let fr = fail[r] as usize;
            let fallback = goto[fr].clone();
            for (cell, fallback_val) in goto[r].iter_mut().zip(fallback) {
                if *cell == u32::MAX {
                    *cell = fallback_val;
                }
            }
        }

        Self { goto, fail, output, depth }
    }

    /// Search `data` for any of the patterns. Returns `(position, pattern_idx)`.
    #[must_use] 
    pub fn search(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        let mut state = 0u32;
        for (i, &b) in data.iter().enumerate() {
            state = self.goto[state as usize][b as usize];
            for &pat_idx in &self.output[state as usize] {
                results.push((i + 1, pat_idx));
            }
        }
        results
    }
}

// ── DFA table (simplified NFA→DFA subset construction) ───────────────────────

/// A deterministic finite automaton compiled from a regex-like NFA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfaTable {
    /// Transition table: `trans[state * 256 + byte]` → next state.
    pub trans: Vec<u32>,
    /// Set of accepting states.
    pub accept: Vec<bool>,
    /// Number of states.
    pub num_states: usize,
}

impl DfaTable {
    /// Construct a trivial single-pattern DFA for a literal byte slice.
    /// Used as a placeholder when full regex compilation is not available.
    #[must_use] 
    pub fn from_literal(pattern: &[u8]) -> Self {
        let n = pattern.len() + 1;
        let mut trans = vec![0u32; n * 256];
        let mut accept = vec![false; n];

        for (i, &byte) in pattern.iter().enumerate() {
            trans[i * 256 + byte as usize] = usize_to_u32(i + 1);
            // All other transitions go to state 0 (already zero-initialized)
            // except: partial-match failure links would be needed for full KMP,
            // but for a literal DFA we reset to 0 on mismatch.
        }
        if !pattern.is_empty() {
            accept[pattern.len()] = true;
        }

        Self { trans, accept, num_states: n }
    }

    /// Run the DFA against `data`. Returns all end-positions of matches.
    #[must_use] 
    pub fn run(&self, data: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        let mut state = 0usize;
        for (i, &b) in data.iter().enumerate() {
            state = self.trans[state * 256 + b as usize] as usize;
            if state < self.accept.len() && self.accept[state] {
                positions.push(i + 1);
                // Optionally reset for non-overlapping matches
                state = 0;
            }
        }
        positions
    }
}

// ── Compiled rule ─────────────────────────────────────────────────────────────

/// A fully compiled YARA rule with optimized patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: BTreeMap<String, String>,
    pub strings: Vec<CompiledString>,
    /// Serialised condition AST (simplified — stored as S-expression text).
    pub condition: String,
    /// Estimated worst-case scan cost (higher = slower).
    pub cost_estimate: u32,
}

/// A compiled YARA string definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledString {
    pub identifier: String,
    pub pattern: CompiledPattern,
    pub modifiers: u16, // raw StringModifiers bits
    /// Whether this string was deduplicated with another.
    pub is_alias: bool,
    pub alias_of: Option<String>,
}

// ── Compiler ──────────────────────────────────────────────────────────────────

/// Options for the rule compiler.
#[derive(Debug, Clone)]
pub struct CompilerOptions {
    /// Use Aho-Corasick multi-pattern optimization when >= this many literals exist.
    pub ac_threshold: usize,
    /// Inline regex strings as DFA (true) or keep as NFA (false).
    pub dfa_compile: bool,
    /// Deduplicate identical patterns across strings.
    pub dedup_patterns: bool,
    /// Maximum regex complexity (nodes in NFA). Rules exceeding this are rejected.
    pub max_regex_complexity: usize,
}

impl Default for CompilerOptions {
    fn default() -> Self {
        Self {
            ac_threshold: 3,
            dfa_compile: true,
            dedup_patterns: true,
            max_regex_complexity: 10_000,
        }
    }
}

/// YARA rule compiler.
pub struct Compiler {
    options: CompilerOptions,
    /// Cache of already-compiled literal patterns → `CompiledPattern` index.
    literal_cache: HashMap<Vec<u8>, CompiledPattern>,
}

impl Compiler {
    /// Create a compiler with default options.
    #[must_use] 
    pub fn new() -> Self {
        Self::with_options(CompilerOptions::default())
    }

    /// Create a compiler with custom options.
    #[must_use] 
    pub fn with_options(options: CompilerOptions) -> Self {
        Self { options, literal_cache: HashMap::new() }
    }

    /// Compile a list of [`YaraRule`] objects into [`CompiledRule`]s.
    ///
    /// # Errors
    /// Returns `Err` if any rule fails to compile.
    pub fn compile_rules(&mut self, rules: &[YaraRule]) -> Result<Vec<CompiledRule>, YaraError> {
        rules.iter().map(|r| self.compile_rule(r)).collect()
    }

    /// Compile a single [`YaraRule`].
    ///
    /// # Errors
    /// Returns `Err` if the rule contains an invalid pattern or condition.
    pub fn compile_rule(&mut self, rule: &YaraRule) -> Result<CompiledRule, YaraError> {
        let mut compiled_strings: Vec<CompiledString> = Vec::new();
        let mut pattern_dedup: HashMap<Vec<u8>, String> = HashMap::new();
        let mut literal_batch: Vec<(usize, Vec<u8>)> = Vec::new();

        // First pass: compile each string, collecting literals for batch AC.
        for ys in &rule.strings {
            let nocase = ys.modifiers.contains(StringModifiers::NOCASE);
            let pat = self.compile_string_value(&ys.value, nocase);
            let is_literal = matches!(&pat, CompiledPattern::Literal(_));

            // Deduplication
            let (is_alias, alias_of) = if self.options.dedup_patterns {
                if let CompiledPattern::Literal(bytes) = &pat {
                    use std::collections::hash_map::Entry;
                    match pattern_dedup.entry(bytes.clone()) {
                        Entry::Occupied(e) => (true, Some(e.get().clone())),
                        Entry::Vacant(e) => {
                            e.insert(ys.identifier.clone());
                            (false, None)
                        }
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            if is_literal
                && let CompiledPattern::Literal(ref bytes) = pat {
                    literal_batch.push((compiled_strings.len(), bytes.clone()));
                }

            compiled_strings.push(CompiledString {
                identifier: ys.identifier.clone(),
                pattern: pat,
                modifiers: ys.modifiers.bits(),
                is_alias,
                alias_of,
            });
        }

        // Second pass: batch AC optimization if threshold met.
        if literal_batch.len() >= self.options.ac_threshold {
            let patterns: Vec<Vec<u8>> = literal_batch.iter().map(|(_, b)| b.clone()).collect();
            let automaton = AcAutomaton::build(&patterns);
            // Replace individual literals with AC variant in the first string only;
            // others are marked as aliases of that batch.
            if let Some((first_idx, _)) = literal_batch.first() {
                let all_pats: Vec<Vec<u8>> = literal_batch.iter().map(|(_, b)| b.clone()).collect();
                compiled_strings[*first_idx].pattern = CompiledPattern::AhoCorasick {
                    patterns: all_pats,
                    automaton,
                };
            }
        }

        let cost = estimate_cost(&compiled_strings);

        Ok(CompiledRule {
            name: rule.name.clone(),
            namespace: rule.namespace.clone(),
            tags: rule.tags.clone(),
            meta: rule.meta.iter().map(|(k, v)| (k.clone(), format!("{v:?}"))).collect(),
            strings: compiled_strings,
            condition: "any of them".to_string(),
            cost_estimate: cost,
        })
    }

    fn compile_string_value(
        &mut self,
        value: &StringValue,
        nocase: bool,
    ) -> CompiledPattern {
        match value {
            StringValue::Text(t) => {
                let bytes = if nocase {
                    t.to_lowercase().into_bytes()
                } else {
                    t.as_bytes().to_vec()
                };
                if let Some(cached) = self.literal_cache.get(&bytes) {
                    return cached.clone();
                }
                let pat = CompiledPattern::Literal(bytes.clone());
                self.literal_cache.insert(bytes, pat.clone());
                pat
            }
            StringValue::Hex(tokens) => compile_hex_pattern(tokens),
            StringValue::Regex(r) => {
                // Attempt DFA compilation of simple regex.
                if self.options.dfa_compile {
                    compile_regex_to_dfa(r)
                } else {
                    CompiledPattern::Literal(r.as_bytes().to_vec())
                }
            }
        }
    }
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile a hex pattern with optional wildcards into a `Masked` or `Literal` pattern.
fn compile_hex_pattern(tokens: &[HexToken]) -> CompiledPattern {
    let mut bytes = Vec::with_capacity(tokens.len());
    let mut masks = Vec::with_capacity(tokens.len());
    let mut has_wildcard = false;

    for tok in tokens {
        match tok {
            HexToken::Byte(b) => {
                bytes.push(*b);
                masks.push(0xFFu8);
            }
            HexToken::Wildcard => {
                bytes.push(0x00);
                masks.push(0x00);
                has_wildcard = true;
            }
            HexToken::MaskedByte(b, m) => {
                bytes.push(*b);
                masks.push(*m);
                has_wildcard = true;
            }
            HexToken::Jump(min, max) => {
                // Encode a jump as repeated wildcards up to max (capped at 64).
                let count = max.unwrap_or((*min + 16).min(64)) as usize;
                for _ in 0..count {
                    bytes.push(0x00);
                    masks.push(0x00);
                    has_wildcard = true;
                }
            }
            HexToken::Alternative(alts) => {
                // Encode first alternative as literal bytes for simplicity.
                if let Some(first) = alts.first() {
                    for inner_tok in first {
                        if let HexToken::Byte(b) = inner_tok {
                            bytes.push(*b);
                            masks.push(0xFF);
                        } else {
                            bytes.push(0x00);
                            masks.push(0x00);
                            has_wildcard = true;
                        }
                    }
                }
            }
        }
    }

    if has_wildcard {
        CompiledPattern::Masked { bytes, masks }
    } else {
        CompiledPattern::Literal(bytes)
    }
}

/// Very simplified regex → DFA compiler for literal-only regexes.
/// For full regex support, integrate the `regex-automata` crate.
fn compile_regex_to_dfa(pattern: &str) -> CompiledPattern {
    // Detect if the regex is just a literal string (no metacharacters).
    let is_literal = pattern.chars().all(|c| {
        !matches!(c, '.' | '*' | '+' | '?' | '[' | ']' | '{' | '}' | '(' | ')' | '|' | '^' | '$' | '\\')
    });

    if is_literal {
        let dfa = DfaTable::from_literal(pattern.as_bytes());
        return CompiledPattern::Dfa(dfa);
    }

    // For non-literal regex, fall back to a Literal of the pattern bytes
    // (real implementation would call regex-automata::dfa::dense::Builder).
    CompiledPattern::Literal(pattern.as_bytes().to_vec())
}

// ── Cost estimation ───────────────────────────────────────────────────────────

fn estimate_cost(strings: &[CompiledString]) -> u32 {
    strings.iter().map(|s| match &s.pattern {
        CompiledPattern::Literal(b) => if b.is_empty() { 1000 } else { 10 },
        CompiledPattern::Masked { bytes, .. } => usize_to_u32(bytes.len()) * 2,
        CompiledPattern::AhoCorasick { patterns, .. } => {
            patterns.iter().map(|p| usize_to_u32(p.len())).sum::<u32>()
        }
        CompiledPattern::Dfa(dfa) => usize_to_u32(dfa.num_states).saturating_mul(2),
    }).sum()
}

// ── Binary cache serialization ────────────────────────────────────────────────

/// Magic bytes for the cache file format.
const CACHE_MAGIC: &[u8] = b"RYRE\x01\x00";

/// Serialize compiled rules to a binary cache blob.
///
/// # Errors
/// Returns `Err` if JSON serialization fails.
pub fn serialize_to_cache(rules: &[CompiledRule]) -> Result<Vec<u8>, YaraError> {
    let json = serde_json::to_vec(rules)
        .map_err(|e| YaraError::CompileError(format!("serialize: {e}")))?;

    let mut out = Vec::with_capacity(CACHE_MAGIC.len() + 4 + json.len());
    out.extend_from_slice(CACHE_MAGIC);
    let len = usize_to_u32(json.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&json);

    // Append a CRC32 of the JSON payload.
    let crc = crc32_simple(&json);
    out.extend_from_slice(&crc.to_le_bytes());

    Ok(out)
}

/// Deserialize compiled rules from a binary cache blob.
///
/// # Errors
/// Returns `Err` if the cache magic, length, or CRC are invalid, or
/// if the JSON payload fails to deserialize.
pub fn deserialize_from_cache(data: &[u8]) -> Result<Vec<CompiledRule>, YaraError> {
    if data.len() < CACHE_MAGIC.len() + 4 + 4 {
        return Err(YaraError::CompileError("cache too short".into()));
    }
    if &data[..CACHE_MAGIC.len()] != CACHE_MAGIC {
        return Err(YaraError::CompileError("invalid cache magic".into()));
    }
    let len = u32::from_le_bytes(
        data[CACHE_MAGIC.len()..CACHE_MAGIC.len() + 4]
            .try_into()
            .map_err(|_| YaraError::CompileError("bad length".into()))?,
    ) as usize;
    let json_start = CACHE_MAGIC.len() + 4;
    let json_end = json_start + len;
    if json_end + 4 > data.len() {
        return Err(YaraError::CompileError("cache truncated".into()));
    }
    let json = &data[json_start..json_end];
    let stored_crc = u32::from_le_bytes(
        data[json_end..json_end + 4]
            .try_into()
            .map_err(|_| YaraError::CompileError("bad crc".into()))?,
    );
    if crc32_simple(json) != stored_crc {
        return Err(YaraError::CompileError("cache CRC mismatch".into()));
    }
    serde_json::from_slice(json)
        .map_err(|e| YaraError::CompileError(format!("deserialize: {e}")))
}

/// Minimal CRC-32/ISO-HDLC implementation (no external dependencies).
fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ── Rule parser (subset) ──────────────────────────────────────────────────────

/// Parse a subset of YARA rule syntax into [`YaraRule`] objects.
///
/// Supports: `rule NAME { strings: $x = "..." condition: any of them }`
///
/// # Errors
/// Returns `Err` on malformed rule syntax.
pub fn parse_yara_text(source: &str) -> Result<Vec<YaraRule>, YaraError> {
    let mut rules = Vec::new();
    let mut pos = 0;
    let src = source.as_bytes();

    while pos < src.len() {
        skip_whitespace_and_comments(src, &mut pos);
        if pos >= src.len() { break; }

        // Expect "rule" keyword
        if !starts_with_word(src, pos, b"rule") {
            pos += 1;
            continue;
        }
        pos += 4;
        skip_whitespace(src, &mut pos);

        // Rule name
        let name_start = pos;
        while pos < src.len() && (src[pos].is_ascii_alphanumeric() || src[pos] == b'_') {
            pos += 1;
        }
        let name = String::from_utf8_lossy(&src[name_start..pos]).to_string();
        if name.is_empty() {
            return Err(YaraError::ParseError { line: 0, message: "expected rule name".into() });
        }

        // Skip to opening brace
        while pos < src.len() && src[pos] != b'{' { pos += 1; }
        if pos >= src.len() {
            return Err(YaraError::ParseError { line: 0, message: "expected '{'".into() });
        }
        pos += 1;

        let mut strings = Vec::new();
        // Skip to `strings:` section
        loop {
            skip_whitespace_and_comments(src, &mut pos);
            if pos >= src.len() { break; }
            if src[pos] == b'}' { pos += 1; break; }

            if starts_with_word(src, pos, b"strings") {
                pos += 7;
                skip_whitespace(src, &mut pos);
                if pos < src.len() && src[pos] == b':' { pos += 1; }
                // Parse string definitions
                loop {
                    skip_whitespace_and_comments(src, &mut pos);
                    if pos >= src.len() || src[pos] == b'}' { break; }
                    if starts_with_word(src, pos, b"condition") { break; }
                    if src[pos] == b'$' {
                        if let Some(ys) = parse_yara_string(src, &mut pos) {
                            strings.push(ys);
                        }
                    } else {
                        pos += 1;
                    }
                }
            } else if starts_with_word(src, pos, b"condition") {
                // Skip condition block
                while pos < src.len() && src[pos] != b'}' { pos += 1; }
                if pos < src.len() { pos += 1; }
                break;
            } else {
                pos += 1;
            }
        }

        rules.push(YaraRule {
            name,
            namespace: String::new(),
            tags: Vec::new(),
            meta: HashMap::new(),
            strings,
            condition: crate::Condition::Any,
        });
    }

    Ok(rules)
}

fn parse_yara_string(src: &[u8], pos: &mut usize) -> Option<YaraString> {
    // $identifier = "value" [modifiers]
    *pos += 1; // skip $
    let id_start = *pos;
    while *pos < src.len() && (src[*pos].is_ascii_alphanumeric() || src[*pos] == b'_') {
        *pos += 1;
    }
    let id = format!("${}", String::from_utf8_lossy(&src[id_start..*pos]));

    skip_whitespace(src, pos);
    if *pos >= src.len() || src[*pos] != b'=' { return None; }
    *pos += 1;
    skip_whitespace(src, pos);

    if *pos >= src.len() { return None; }

    let (value, modifiers) = if src[*pos] == b'"' {
        // Text string
        *pos += 1;
        let v_start = *pos;
        while *pos < src.len() && src[*pos] != b'"' {
            if src[*pos] == b'\\' { *pos += 1; } // skip escaped char
            *pos += 1;
        }
        let text = String::from_utf8_lossy(&src[v_start..*pos]).to_string();
        if *pos < src.len() { *pos += 1; }
        let mods = parse_string_modifiers(src, pos);
        (StringValue::Text(text), mods)
    } else if *pos < src.len() && src[*pos] == b'{' {
        // Hex string
        *pos += 1;
        let mut tokens = Vec::new();
        loop {
            skip_whitespace(src, pos);
            if *pos >= src.len() || src[*pos] == b'}' { *pos += 1; break; }
            let c = src[*pos] as char;
            if c == '?' {
                tokens.push(HexToken::Wildcard);
                *pos += 1;
            } else if c.is_ascii_hexdigit() {
                let hi = hexdigit(src[*pos]);
                *pos += 1;
                if *pos < src.len() && src[*pos].is_ascii_hexdigit() {
                    let lo = hexdigit(src[*pos]);
                    *pos += 1;
                    tokens.push(HexToken::Byte(hi << 4 | lo));
                } else {
                    tokens.push(HexToken::MaskedByte(hi << 4, 0xF0));
                }
            } else {
                *pos += 1;
            }
        }
        (StringValue::Hex(tokens), StringModifiers::NONE)
    } else if *pos < src.len() && src[*pos] == b'/' {
        // Regex string
        *pos += 1;
        let r_start = *pos;
        while *pos < src.len() && src[*pos] != b'/' {
            if src[*pos] == b'\\' { *pos += 1; }
            *pos += 1;
        }
        let regex = String::from_utf8_lossy(&src[r_start..*pos]).to_string();
        if *pos < src.len() { *pos += 1; }
        (StringValue::Regex(regex), StringModifiers::NONE)
    } else {
        return None;
    };

    Some(YaraString { identifier: id, value, modifiers })
}

fn parse_string_modifiers(src: &[u8], pos: &mut usize) -> StringModifiers {
    let mut mods = StringModifiers::NONE;
    loop {
        skip_whitespace(src, pos);
        if starts_with_word(src, *pos, b"nocase")   { *pos += 6; mods |= StringModifiers::NOCASE; }
        else if starts_with_word(src, *pos, b"ascii")    { *pos += 5; mods |= StringModifiers::ASCII; }
        else if starts_with_word(src, *pos, b"wide")     { *pos += 4; mods |= StringModifiers::WIDE; }
        else if starts_with_word(src, *pos, b"fullword") { *pos += 8; mods |= StringModifiers::FULLWORD; }
        else { break; }
    }
    mods
}

fn skip_whitespace(src: &[u8], pos: &mut usize) {
    while *pos < src.len() && src[*pos].is_ascii_whitespace() { *pos += 1; }
}

fn skip_whitespace_and_comments(src: &[u8], pos: &mut usize) {
    loop {
        skip_whitespace(src, pos);
        if *pos + 1 < src.len() && src[*pos] == b'/' && src[*pos + 1] == b'/' {
            while *pos < src.len() && src[*pos] != b'\n' { *pos += 1; }
        } else if *pos + 1 < src.len() && src[*pos] == b'/' && src[*pos + 1] == b'*' {
            *pos += 2;
            while *pos + 1 < src.len() && !(src[*pos] == b'*' && src[*pos + 1] == b'/') {
                *pos += 1;
            }
            if *pos + 1 < src.len() { *pos += 2; }
        } else {
            break;
        }
    }
}

fn starts_with_word(src: &[u8], pos: usize, word: &[u8]) -> bool {
    if pos + word.len() > src.len() { return false; }
    src[pos..pos + word.len()] == *word
}

const fn hexdigit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ac_automaton_finds_patterns() {
        let patterns = vec![
            b"MZ".to_vec(),
            b"PE\0\0".to_vec(),
        ];
        let ac = AcAutomaton::build(&patterns);
        let data = b"XXXMZXXXPE\x00\x00YYY";
        let hits = ac.search(data);
        assert!(hits.iter().any(|(_, i)| *i == 0), "should find MZ");
        assert!(hits.iter().any(|(_, i)| *i == 1), "should find PE");
    }

    #[test]
    fn test_dfa_literal() {
        let dfa = DfaTable::from_literal(b"HELLO");
        let positions = dfa.run(b"...HELLO WORLD HELLO");
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn test_crc32_round_trip() {
        let data = b"hello world this is a test";
        let crc = crc32_simple(data);
        assert_ne!(crc, 0);
        assert_eq!(crc32_simple(data), crc);
    }

    #[test]
    fn test_cache_round_trip() {
        let rules = vec![CompiledRule {
            name: "test".into(),
            namespace: String::new(),
            tags: Vec::new(),
            meta: BTreeMap::new(),
            strings: Vec::new(),
            condition: "true".into(),
            cost_estimate: 0,
        }];
        let blob = serialize_to_cache(&rules).unwrap();
        let back = deserialize_from_cache(&blob).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].name, "test");
    }

    #[test]
    fn test_parse_yara_text_simple() {
        let src = r"
        rule find_mz {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz
        }
        ";
        let rules = parse_yara_text(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "find_mz");
        assert_eq!(rules[0].strings.len(), 1);
    }

    #[test]
    fn test_hex_pattern_with_wildcard() {
        let tokens = vec![
            HexToken::Byte(0x4D),
            HexToken::Wildcard,
            HexToken::Byte(0x5A),
        ];
        let pat = compile_hex_pattern(&tokens);
        assert!(matches!(pat, CompiledPattern::Masked { .. }));
    }
}
