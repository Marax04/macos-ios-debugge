//! Symbol search: fuzzy and exact search over symbol tables.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt;

use crate::{Symbol, SymKind};

// ── SearchMode ────────────────────────────────────────────────────────────────

/// How the query string is matched against symbol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum SearchMode {
    /// Case-sensitive exact match.
    Exact,
    /// Case-insensitive substring match.
    Contains,
    /// Case-insensitive prefix match.
    Prefix,
    /// Case-insensitive fuzzy match (subsequence).
    #[default]
    Fuzzy,
    /// Wildcard: `*` matches any sequence, `?` matches one character.
    Wildcard,
}


impl fmt::Display for SearchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SearchQuery ───────────────────────────────────────────────────────────────

/// A search query with optional filters.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// The search string.
    pub text: String,
    /// How to match `text` against symbol names.
    pub mode: SearchMode,
    /// Restrict to one or more symbol kinds (empty = all kinds).
    pub kinds: Vec<SymKind>,
    /// Restrict to symbols in a specific module/library (empty = all).
    pub module: Option<String>,
    /// Maximum number of results to return (0 = unlimited).
    pub max_results: usize,
    /// Minimum fuzzy score (0–100).  Ignored in non-fuzzy modes.
    pub min_score: u8,
}

impl SearchQuery {
    /// Create a fuzzy query for `text` with default limits (200 results, score ≥ 30).
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mode: SearchMode::Fuzzy,
            kinds: Vec::new(),
            module: None,
            max_results: 200,
            min_score: 30,
        }
    }

    /// Create an exact-match query for `text`.
    #[must_use]
    pub fn exact(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mode: SearchMode::Exact,
            ..Self::new("")
        }
    }

    /// Set the search mode (builder style).
    #[must_use]
    pub const fn with_mode(mut self, mode: SearchMode) -> Self {
        self.mode = mode;
        self
    }

    /// Restrict results to an additional symbol kind (builder style).
    #[must_use]
    pub fn with_kind(mut self, kind: SymKind) -> Self {
        self.kinds.push(kind);
        self
    }

    /// Restrict results to a module (builder style).
    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Cap the number of results (builder style).
    #[must_use]
    pub const fn with_max(mut self, n: usize) -> Self {
        self.max_results = n;
        self
    }
}

// ── SearchResult ──────────────────────────────────────────────────────────────

/// A single match returned by a search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The matched symbol.
    pub symbol: Symbol,
    /// Match score (0–100; higher = better).  Always 100 for exact/prefix/contains.
    pub score: u8,
    /// Byte offsets in `symbol.name` that matched the query (for highlighting).
    pub match_positions: Vec<usize>,
}

impl SearchResult {
    /// Build a perfect-score result (score 100, no highlight positions) for `symbol`.
    #[must_use]
    pub const fn exact_match(symbol: Symbol) -> Self {
        Self {
            symbol,
            score: 100,
            match_positions: Vec::new(),
        }
    }
}

impl PartialEq for SearchResult {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.symbol.name == other.symbol.name
    }
}

impl Eq for SearchResult {}

impl PartialOrd for SearchResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SearchResult {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher score first; break ties by shorter name first.
        other
            .score
            .cmp(&self.score)
            .then_with(|| self.symbol.name.len().cmp(&other.symbol.name.len()))
            .then_with(|| self.symbol.name.cmp(&other.symbol.name))
    }
}

impl fmt::Display for SearchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:3}] {}", self.score, self.symbol.name)
    }
}

// ── Fuzzy matching internals ──────────────────────────────────────────────────

/// Compute a fuzzy subsequence score (0–100) for matching `needle` against `haystack`.
///
/// Returns `None` if `needle` is not a subsequence of `haystack`.
/// Returns `(score, positions)` on success.
#[must_use]
pub fn fuzzy_score(needle: &str, haystack: &str) -> Option<(u8, Vec<usize>)> {
    if needle.is_empty() {
        return Some((100, Vec::new()));
    }

    // Lowercase per-character rather than via `str::to_lowercase`, which is not
    // length-preserving (U+0130 lowercases to two chars). A whole-string
    // lowercase would desynchronise `haystack_lower` indices from
    // `haystack_chars`, and the boundary-bonus loop below indexes the latter
    // with positions collected from the former.
    let needle_lower: Vec<char> = needle
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect();
    let haystack_chars: Vec<char> = haystack.chars().collect();
    let haystack_lower: Vec<char> = haystack_chars
        .iter()
        .map(|c| c.to_lowercase().next().unwrap_or(*c))
        .collect();

    let mut positions: Vec<usize> = Vec::new();
    let mut ni = 0usize;

    for (hi, &hc) in haystack_lower.iter().enumerate() {
        if ni < needle_lower.len() && hc == needle_lower[ni] {
            positions.push(hi);
            ni += 1;
        }
    }

    if ni < needle_lower.len() {
        return None; // Not a subsequence.
    }

    // Score computation:
    // 1. Penalise by gap between matched characters (prefer contiguous matches).
    // 2. Bonus for matching at word boundaries.
    // 3. Bonus for prefix match.
    let mut gap_penalty: i32 = 0;
    for w in positions.windows(2) {
        let gap_usize = w[1] - w[0];
        let gap = i32::try_from(gap_usize).unwrap_or(i32::MAX).saturating_sub(1);
        gap_penalty = gap_penalty.saturating_add(gap);
    }

    let mut boundary_bonus: i32 = 0;
    for &pos in &positions {
        if pos == 0 {
            boundary_bonus += 10;
        } else {
            let prev = haystack_chars[pos - 1];
            if prev == '_' || prev == ':' || prev == '.' || prev == '-' || !prev.is_alphanumeric() {
                boundary_bonus += 5;
            }
            // CamelCase boundary.
            if haystack_chars[pos].is_uppercase() && !prev.is_uppercase() {
                boundary_bonus += 3;
            }
        }
    }

    // Integer-only length-ratio: floor(100 * needle / haystack), saturating.
    let needle_len = needle.len();
    let haystack_len = haystack.len().max(1);
    let len_score_usize = needle_len.saturating_mul(100) / haystack_len;
    let len_score = i32::try_from(len_score_usize.min(100)).unwrap_or(100);
    let base = len_score
        .saturating_add(boundary_bonus)
        .saturating_sub(gap_penalty);
    let score = u8::try_from(base.clamp(1, 100)).unwrap_or(1);

    Some((score, positions))
}

// ── Wildcard matching ────────────────────────────────────────────────────────

/// Match `pattern` (with `*` and `?`) against `text` (case-insensitive).
#[must_use]
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    wildcard_match_chars(&p, &t)
}

/// Classic greedy wildcard matcher with star backtracking: O(pn + tn) time and
/// O(1) additional memory. The previous full DP table allocated
/// `(pn + 1) * (tn + 1)` bools — unbounded for long mangled symbol names.
fn wildcard_match_chars(p: &[char], t: &[char]) -> bool {
    let (pn, tn) = (p.len(), t.len());
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last '*' in the pattern, and the text position it was
    // matched against, so we can backtrack and let it consume one more char.
    let mut star: Option<(usize, usize)> = None;

    while ti < tn {
        if pi < pn && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pn && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            // Mismatch: let the last '*' absorb one more text character.
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, ti));
        } else {
            return false;
        }
    }

    // Trailing '*'s can match the empty remainder.
    while pi < pn && p[pi] == '*' {
        pi += 1;
    }
    pi == pn
}

// ── SymbolSearch ─────────────────────────────────────────────────────────────

/// Symbol search engine.  Owns no symbols itself; operates on slices.
#[derive(Debug, Default, Clone)]
pub struct SymbolSearch {
    /// Cache of the last query for repeated access.
    last_query: Option<String>,
}

impl SymbolSearch {
    /// Create a search engine with no cached query.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `query` against `symbols` and return sorted results.
    #[must_use]
    pub fn search(&mut self, symbols: &[Symbol], query: &SearchQuery) -> Vec<SearchResult> {
        self.last_query = Some(query.text.clone());

        let mut heap: BinaryHeap<SearchResult> = BinaryHeap::new();

        for sym in symbols {
            // Kind filter.
            if !query.kinds.is_empty() && !query.kinds.contains(&sym.kind) {
                continue;
            }

            // Module filter.
            if let Some(ref module) = query.module
                && !sym
                    .source_file
                    .as_deref()
                    .unwrap_or("")
                    .contains(module.as_str())
                {
                    continue;
                }

            if let Some(result) = Self::match_symbol(sym, query)
                && result.score >= query.min_score {
                    heap.push(result);
                }
        }

        let limit = if query.max_results == 0 {
            usize::MAX
        } else {
            query.max_results
        };

        let mut results: Vec<SearchResult> = heap.into_sorted_vec();
        results.truncate(limit);
        results
    }

    fn match_symbol(sym: &Symbol, query: &SearchQuery) -> Option<SearchResult> {
        let name = &sym.name;
        let text = &query.text;

        match query.mode {
            SearchMode::Exact => {
                if name == text {
                    Some(SearchResult::exact_match(sym.clone()))
                } else {
                    None
                }
            }
            SearchMode::Contains => {
                let nl = name.to_lowercase();
                let tl = text.to_lowercase();
                if nl.contains(&tl) {
                    let mut r = SearchResult::exact_match(sym.clone());
                    let start = nl.find(&tl).unwrap_or(0);
                    r.match_positions = (start..start + tl.len()).collect();
                    Some(r)
                } else {
                    None
                }
            }
            SearchMode::Prefix => {
                if name.to_lowercase().starts_with(&text.to_lowercase()) {
                    let mut r = SearchResult::exact_match(sym.clone());
                    r.match_positions = (0..text.len()).collect();
                    Some(r)
                } else {
                    None
                }
            }
            SearchMode::Fuzzy => {
                let (score, positions) = fuzzy_score(text, name)?;
                Some(SearchResult {
                    symbol: sym.clone(),
                    score,
                    match_positions: positions,
                })
            }
            SearchMode::Wildcard => {
                if wildcard_match(text, name) {
                    Some(SearchResult::exact_match(sym.clone()))
                } else {
                    None
                }
            }
        }
    }

    /// Convenience: fuzzy search with default settings.
    #[must_use]
    pub fn fuzzy_search(&mut self, symbols: &[Symbol], text: &str) -> Vec<SearchResult> {
        let q = SearchQuery::new(text);
        self.search(symbols, &q)
    }

    /// Last query string.
    #[must_use]
    pub fn last_query(&self) -> Option<&str> {
        self.last_query.as_deref()
    }
}

// ── Free-function fuzzy_search ────────────────────────────────────────────────

/// Convenience function: fuzzy search `symbols` for `text`, return sorted results.
#[must_use]
pub fn fuzzy_search(symbols: &[Symbol], text: &str) -> Vec<SearchResult> {
    SymbolSearch::new().fuzzy_search(symbols, text)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SymKind;

    fn sym(name: &str, kind: SymKind) -> Symbol {
        Symbol::new(name.to_owned(), 0, kind)
    }

    fn syms() -> Vec<Symbol> {
        vec![
            sym("main", SymKind::Function),
            sym("malloc", SymKind::Function),
            sym("memcpy", SymKind::Function),
            sym("GlobalCounter", SymKind::Data),
            sym("MyStruct::new", SymKind::Function),
            sym("MyStruct::drop", SymKind::Function),
            sym("printf", SymKind::Function),
            sym("rust_panic", SymKind::Function),
        ]
    }

    #[test]
    fn exact_match() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::exact("main");
        let r = s.search(&syms(), &q);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].symbol.name, "main");
    }

    #[test]
    fn exact_no_match() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::exact("Main");
        let r = s.search(&syms(), &q);
        assert!(r.is_empty());
    }

    #[test]
    fn contains_match() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("mem").with_mode(SearchMode::Contains);
        let r = s.search(&syms(), &q);
        // memcpy contains "mem"
        assert!(r.iter().any(|x| x.symbol.name == "memcpy"));
    }

    #[test]
    fn prefix_match() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("My").with_mode(SearchMode::Prefix);
        let r = s.search(&syms(), &q);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.symbol.name.starts_with("My")));
    }

    #[test]
    fn fuzzy_subsequence_match() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("mc").with_mode(SearchMode::Fuzzy);
        let r = s.search(&syms(), &q);
        // "memcpy" is a match for "mc"
        assert!(r.iter().any(|x| x.symbol.name == "memcpy"), "{r:?}");
    }

    #[test]
    fn fuzzy_no_match_for_impossible_subsequence() {
        let (score, _) = fuzzy_score("xyz", "main").unwrap_or((0, vec![]));
        assert_eq!(score, 0);
    }

    #[test]
    fn fuzzy_score_contiguous_higher() {
        let (s1, _) = fuzzy_score("mal", "malloc").unwrap();
        let (s2, _) = fuzzy_score("mal", "m_a_l_l_o_c").unwrap();
        assert!(s1 > s2);
    }

    #[test]
    fn kind_filter() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("").with_mode(SearchMode::Contains).with_kind(SymKind::Data);
        let r = s.search(&syms(), &q);
        assert!(r.iter().all(|x| x.symbol.kind == SymKind::Data));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn max_results_limit() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("").with_mode(SearchMode::Contains).with_max(3);
        let r = s.search(&syms(), &q);
        assert!(r.len() <= 3);
    }

    #[test]
    fn wildcard_star() {
        assert!(wildcard_match("My*::new", "MyStruct::new"));
        assert!(!wildcard_match("My*::new", "MyStruct::drop"));
    }

    #[test]
    fn wildcard_question_mark() {
        assert!(wildcard_match("mai?", "main"));
        assert!(!wildcard_match("mai?", "malloc"));
    }

    #[test]
    fn wildcard_search_mode() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("My*").with_mode(SearchMode::Wildcard);
        let r = s.search(&syms(), &q);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn results_sorted_by_score() {
        let syms = vec![
            sym("m", SymKind::Function),
            sym("main", SymKind::Function),
            sym("malloc", SymKind::Function),
        ];
        let mut s = SymbolSearch::new();
        let r = s.fuzzy_search(&syms, "main");
        if r.len() >= 2 {
            assert!(r[0].score >= r[1].score);
        }
    }

    #[test]
    fn fuzzy_search_free_fn() {
        let syms = vec![sym("printf", SymKind::Function), sym("main", SymKind::Function)];
        let r = fuzzy_search(&syms, "mai");
        assert!(!r.is_empty());
        assert_eq!(r[0].symbol.name, "main");
    }

    #[test]
    fn last_query_updated() {
        let mut s = SymbolSearch::new();
        let q = SearchQuery::new("hello");
        let _ = s.search(&[], &q);
        assert_eq!(s.last_query(), Some("hello"));
    }

    // -- Regression: Unicode-safe fuzzy_score, allocation-free wildcard ------

    #[test]
    fn fuzzy_score_handles_length_changing_lowercase() {
        // U+0130 lowercases to TWO chars (U+0069 U+0307), so a whole-string
        // lowercase desynchronises indices from the original char vector and
        // the boundary-bonus loop then indexed out of bounds.
        let haystack = "\u{0130}nit_module";
        assert!(fuzzy_score("init", haystack).is_some());
        assert!(fuzzy_score("nit", haystack).is_some());
    }

    #[test]
    fn fuzzy_score_positions_index_original_chars() {
        let (_, positions) = fuzzy_score("bc", "abc").unwrap();
        assert_eq!(positions, vec![1, 2]);
    }

    #[test]
    fn wildcard_semantics_preserved() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*c", "abbbc"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
        assert!(wildcard_match("*.txt", "notes.txt"));
        assert!(!wildcard_match("*.txt", "notes.md"));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "x"));
        assert!(wildcard_match("**", "abc"));
        assert!(wildcard_match("a*b*c", "axxbyyc"));
        assert!(!wildcard_match("a*b*c", "axxbyy"));
        assert!(wildcard_match("ABC*", "abcdef"));
    }

    #[test]
    fn wildcard_long_input_does_not_allocate_a_matrix() {
        // Previously allocated a (pattern+1) x (text+1) bool matrix: ~10 MB
        // and 1001 separate allocations for this single call.
        let pattern: String = "*".repeat(1_000);
        let text: String = "a".repeat(10_000);
        assert!(wildcard_match(&pattern, &text));
    }

}
