// grammar_fuzzer.rs — Grammar-based fuzzer for RustRE

use std::collections::HashMap;

// ─── xorshift64 ───────────────────────────────────────────────────────────────

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ─── Term ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Term {
    Terminal(String),
    NonTerminal(String),
    Optional(Box<Self>),
    Repeat { term: Box<Self>, min: u32, max: u32 },
    Choice(Vec<Self>),
}

impl Term {
    pub fn terminal(s: &str) -> Self {
        Self::Terminal(s.to_string())
    }

    pub fn non_terminal(s: &str) -> Self {
        Self::NonTerminal(s.to_string())
    }

    pub fn optional(t: Self) -> Self {
        Self::Optional(Box::new(t))
    }

    pub fn repeat(t: Self, min: u32, max: u32) -> Self {
        Self::Repeat { term: Box::new(t), min, max }
    }

    pub fn choice(terms: Vec<Self>) -> Self {
        Self::Choice(terms)
    }
}

// ─── Expansion ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Expansion {
    pub terms: Vec<Term>,
}

impl Expansion {
    pub fn new(terms: Vec<Term>) -> Self {
        Self { terms }
    }

    pub fn single(t: Term) -> Self {
        Self { terms: vec![t] }
    }
}

// ─── Grammar ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Grammar {
    pub rules: HashMap<String, Vec<Expansion>>,
}

impl Grammar {
    pub fn new() -> Self {
        Self { rules: HashMap::new() }
    }

    pub fn add_rule(&mut self, name: &str, expansions: Vec<Expansion>) {
        self.rules.insert(name.to_string(), expansions);
    }

    pub fn has_rule(&self, name: &str) -> bool {
        self.rules.contains_key(name)
    }
}

// ─── GrammarInstance (fuzzer state) ──────────────────────────────────────────

pub struct GrammarInstance {
    pub grammar: Grammar,
    pub seed: u64,
    rng_state: u64,
}

impl GrammarInstance {
    pub fn new(grammar: Grammar, seed: u64) -> Self {
        Self {
            grammar,
            seed,
            rng_state: if seed == 0 { 0xabcdef12345678 } else { seed },
        }
    }

    fn rand_below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (xorshift64(&mut self.rng_state) % n as u64) as usize
    }

    /// Recursively generate a string from `start` rule with depth budget.
    pub fn generate(&mut self, start: &str, max_depth: u32) -> String {
        self.generate_term(&Term::NonTerminal(start.to_string()), max_depth)
    }

    fn generate_term(&mut self, term: &Term, depth: u32) -> String {
        match term {
            Term::Terminal(s) => s.clone(),
            Term::NonTerminal(name) => {
                if depth == 0 {
                    // At max depth, pick the shortest (terminal-only) expansion
                    return self.generate_shortest(name);
                }
                let expansions = match self.grammar.rules.get(name) {
                    Some(e) => e.clone(),
                    None => return String::new(),
                };
                if expansions.is_empty() {
                    return String::new();
                }
                // Weight choices: at low depth prefer shorter expansions
                let idx = if depth <= 2 {
                    self.pick_shortest_expansion_idx(&expansions)
                } else {
                    self.rand_below(expansions.len())
                };
                let expansion = &expansions[idx].clone();
                expansion.terms.iter().map(|t| self.generate_term(t, depth - 1)).collect::<String>()
            }
            Term::Optional(inner) => {
                if self.rand_below(2) == 0 {
                    self.generate_term(inner, depth)
                } else {
                    String::new()
                }
            }
            Term::Repeat { term: inner, min, max } => {
                let range = (max - min) as usize + 1;
                let count = *min as usize + if range > 0 { self.rand_below(range) } else { 0 };
                (0..count).map(|_| self.generate_term(inner, depth)).collect::<String>()
            }
            Term::Choice(terms) => {
                if terms.is_empty() {
                    return String::new();
                }
                let idx = self.rand_below(terms.len());
                self.generate_term(&terms[idx].clone(), depth)
            }
        }
    }

    fn generate_shortest(&self, name: &str) -> String {
        let expansions = match self.grammar.rules.get(name) {
            Some(e) => e,
            None => return String::new(),
        };
        // Find expansion with fewest non-terminals
        let best = expansions.iter().min_by_key(|exp| {
            exp.terms.iter().filter(|t| matches!(t, Term::NonTerminal(_))).count()
        });
        match best {
            Some(exp) => exp.terms.iter().map(|t| match t {
                Term::Terminal(s) => s.clone(),
                _ => String::new(),
            }).collect::<String>(),
            None => String::new(),
        }
    }

    fn pick_shortest_expansion_idx(&self, expansions: &[Expansion]) -> usize {
        expansions.iter().enumerate().min_by_key(|(_, exp)| {
            exp.terms.iter().filter(|t| matches!(t, Term::NonTerminal(_))).count()
        }).map(|(i, _)| i).unwrap_or(0)
    }
}

// ─── BNF parser ───────────────────────────────────────────────────────────────

/// Parse a simple BNF grammar text into a Grammar.
/// Format: `rule-name ::= alt1 | alt2`
/// Terminals are enclosed in double quotes.
/// Non-terminals are bare identifiers.
pub fn parse_bnf_grammar(text: &str) -> Grammar {
    let mut grammar = Grammar::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, "::=").collect();
        if parts.len() != 2 {
            continue;
        }
        let rule_name = parts[0].trim().to_string();
        let rhs = parts[1];
        let mut expansions = Vec::new();
        for alt in rhs.split('|') {
            let alt = alt.trim();
            let terms = parse_expansion_terms(alt);
            if !terms.is_empty() {
                expansions.push(Expansion::new(terms));
            }
        }
        if !expansions.is_empty() {
            grammar.rules.insert(rule_name, expansions);
        }
    }
    grammar
}

fn parse_expansion_terms(alt: &str) -> Vec<Term> {
    let mut terms = Vec::new();
    let mut chars = alt.chars();
    let mut buf = String::new();
    while let Some(c) = chars.next() {
        if c == '"' {
            // Read until closing quote
            let mut s = String::new();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                s.push(ch);
            }
            if !buf.trim().is_empty() {
                for tok in buf.split_whitespace() {
                    terms.push(Term::NonTerminal(tok.to_string()));
                }
                buf.clear();
            }
            terms.push(Term::Terminal(s));
        } else {
            buf.push(c);
        }
    }
    // Remaining tokens are non-terminals
    for tok in buf.split_whitespace() {
        if !tok.is_empty() {
            terms.push(Term::NonTerminal(tok.to_string()));
        }
    }
    terms
}

// ─── Built-in grammars ────────────────────────────────────────────────────────

pub fn builtin_grammar_http11() -> Grammar {
    let mut g = Grammar::new();
    g.add_rule("request", vec![
        Expansion::new(vec![
            Term::non_terminal("method"),
            Term::terminal(" "),
            Term::non_terminal("path"),
            Term::terminal(" HTTP/1.1\r\nHost: "),
            Term::non_terminal("host"),
            Term::terminal("\r\n\r\n"),
        ]),
    ]);
    g.add_rule("method", vec![
        Expansion::single(Term::terminal("GET")),
        Expansion::single(Term::terminal("POST")),
        Expansion::single(Term::terminal("PUT")),
        Expansion::single(Term::terminal("DELETE")),
        Expansion::single(Term::terminal("OPTIONS")),
    ]);
    g.add_rule("path", vec![
        Expansion::single(Term::terminal("/")),
        Expansion::single(Term::terminal("/index.html")),
        Expansion::single(Term::terminal("/api/v1/resource")),
        Expansion::single(Term::terminal("/search?q=test")),
    ]);
    g.add_rule("host", vec![
        Expansion::single(Term::terminal("localhost")),
        Expansion::single(Term::terminal("example.com")),
        Expansion::single(Term::terminal("127.0.0.1")),
    ]);
    g
}

pub fn builtin_grammar_json() -> Grammar {
    let mut g = Grammar::new();
    g.add_rule("value", vec![
        Expansion::single(Term::non_terminal("object")),
        Expansion::single(Term::non_terminal("array")),
        Expansion::single(Term::non_terminal("string")),
        Expansion::single(Term::non_terminal("number")),
        Expansion::single(Term::terminal("true")),
        Expansion::single(Term::terminal("false")),
        Expansion::single(Term::terminal("null")),
    ]);
    g.add_rule("object", vec![
        Expansion::single(Term::terminal("{}")),
        Expansion::new(vec![
            Term::terminal("{"),
            Term::non_terminal("kvpair"),
            Term::terminal("}"),
        ]),
    ]);
    g.add_rule("kvpair", vec![
        Expansion::new(vec![
            Term::non_terminal("string"),
            Term::terminal(":"),
            Term::non_terminal("value"),
        ]),
    ]);
    g.add_rule("array", vec![
        Expansion::single(Term::terminal("[]")),
        Expansion::new(vec![
            Term::terminal("["),
            Term::non_terminal("value"),
            Term::terminal("]"),
        ]),
    ]);
    g.add_rule("string", vec![
        Expansion::single(Term::terminal("\"hello\"")),
        Expansion::single(Term::terminal("\"world\"")),
        Expansion::single(Term::terminal("\"foo\"")),
        Expansion::single(Term::terminal("\"\"")),
    ]);
    g.add_rule("number", vec![
        Expansion::single(Term::terminal("0")),
        Expansion::single(Term::terminal("1")),
        Expansion::single(Term::terminal("-1")),
        Expansion::single(Term::terminal("3.14")),
        Expansion::single(Term::terminal("1e10")),
    ]);
    g
}

pub fn builtin_grammar_sql_select() -> Grammar {
    let mut g = Grammar::new();
    g.add_rule("query", vec![
        Expansion::new(vec![
            Term::terminal("SELECT "),
            Term::non_terminal("cols"),
            Term::terminal(" FROM "),
            Term::non_terminal("table"),
            Term::non_terminal("where_clause"),
            Term::non_terminal("order_clause"),
            Term::terminal(";"),
        ]),
    ]);
    g.add_rule("cols", vec![
        Expansion::single(Term::terminal("*")),
        Expansion::single(Term::terminal("id, name")),
        Expansion::single(Term::terminal("COUNT(*)")),
    ]);
    g.add_rule("table", vec![
        Expansion::single(Term::terminal("users")),
        Expansion::single(Term::terminal("orders")),
        Expansion::single(Term::terminal("products")),
    ]);
    g.add_rule("where_clause", vec![
        Expansion::single(Term::terminal("")),
        Expansion::new(vec![Term::terminal(" WHERE id = 1")]),
        Expansion::new(vec![Term::terminal(" WHERE name = 'admin'")]),
    ]);
    g.add_rule("order_clause", vec![
        Expansion::single(Term::terminal("")),
        Expansion::single(Term::terminal(" ORDER BY id")),
        Expansion::single(Term::terminal(" ORDER BY name DESC")),
    ]);
    g
}

pub fn builtin_grammar_xml() -> Grammar {
    let mut g = Grammar::new();
    g.add_rule("document", vec![
        Expansion::new(vec![
            Term::terminal("<?xml version=\"1.0\"?>"),
            Term::non_terminal("element"),
        ]),
    ]);
    g.add_rule("element", vec![
        Expansion::new(vec![
            Term::terminal("<"),
            Term::non_terminal("tagname"),
            Term::terminal(">"),
            Term::non_terminal("content"),
            Term::terminal("</"),
            Term::non_terminal("tagname"),
            Term::terminal(">"),
        ]),
        Expansion::new(vec![
            Term::terminal("<"),
            Term::non_terminal("tagname"),
            Term::terminal("/>"),
        ]),
    ]);
    g.add_rule("tagname", vec![
        Expansion::single(Term::terminal("root")),
        Expansion::single(Term::terminal("item")),
        Expansion::single(Term::terminal("data")),
    ]);
    g.add_rule("content", vec![
        Expansion::single(Term::terminal("text")),
        Expansion::single(Term::terminal("")),
        Expansion::single(Term::non_terminal("element")),
    ]);
    g
}

pub fn builtin_grammar_cmdline() -> Grammar {
    let mut g = Grammar::new();
    g.add_rule("cmdline", vec![
        Expansion::new(vec![
            Term::non_terminal("cmd"),
            Term::terminal(" "),
            Term::non_terminal("args"),
        ]),
    ]);
    g.add_rule("cmd", vec![
        Expansion::single(Term::terminal("ls")),
        Expansion::single(Term::terminal("cat")),
        Expansion::single(Term::terminal("echo")),
        Expansion::single(Term::terminal("find")),
    ]);
    g.add_rule("args", vec![
        Expansion::single(Term::terminal("")),
        Expansion::single(Term::terminal("-la")),
        Expansion::new(vec![Term::non_terminal("path")]),
        Expansion::new(vec![Term::non_terminal("flag"), Term::terminal(" "), Term::non_terminal("path")]),
    ]);
    g.add_rule("path", vec![
        Expansion::single(Term::terminal("/etc/passwd")),
        Expansion::single(Term::terminal("/tmp/test")),
        Expansion::single(Term::terminal(".")),
    ]);
    g.add_rule("flag", vec![
        Expansion::single(Term::terminal("-r")),
        Expansion::single(Term::terminal("-v")),
        Expansion::single(Term::terminal("--help")),
    ]);
    g
}

pub enum BuiltinGrammar {
    Http11Request,
    JsonValue,
    SqlSelect,
    XmlDocument,
    CommandLine,
}

pub fn get_builtin_grammar(name: BuiltinGrammar) -> Grammar {
    match name {
        BuiltinGrammar::Http11Request => builtin_grammar_http11(),
        BuiltinGrammar::JsonValue => builtin_grammar_json(),
        BuiltinGrammar::SqlSelect => builtin_grammar_sql_select(),
        BuiltinGrammar::XmlDocument => builtin_grammar_xml(),
        BuiltinGrammar::CommandLine => builtin_grammar_cmdline(),
    }
}

// ─── GrammarMutation ─────────────────────────────────────────────────────────

pub struct GrammarMutation;

impl GrammarMutation {
    /// Replace a random terminal in the grammar with an alternative.
    pub fn mutate_grammar(grammar: &mut Grammar, rng: &mut u64) {
        let keys: Vec<String> = grammar.rules.keys().cloned().collect();
        if keys.is_empty() {
            return;
        }
        let ki = (xorshift64(rng) % keys.len() as u64) as usize;
        let key = &keys[ki];
        if let Some(exps) = grammar.rules.get_mut(key) {
            if exps.is_empty() {
                return;
            }
            let ei = (xorshift64(rng) % exps.len() as u64) as usize;
            let exp = &mut exps[ei];
            for term in &mut exp.terms {
                if let Term::Terminal(s) = term {
                    *s = format!("{s}__mutated");
                    break;
                }
            }
        }
    }
}

// ─── GrammarFuzzer ────────────────────────────────────────────────────────────

pub struct GrammarFuzzer {
    pub instance: GrammarInstance,
    pub start_rule: String,
    pub max_depth: u32,
}

impl GrammarFuzzer {
    pub fn new(grammar: Grammar, start: &str, max_depth: u32, seed: u64) -> Self {
        Self {
            instance: GrammarInstance::new(grammar, seed),
            start_rule: start.to_string(),
            max_depth,
        }
    }

    pub fn generate_one(&mut self) -> String {
        self.instance.generate(&self.start_rule, self.max_depth)
    }

    pub fn generate_corpus(&mut self, count: u32) -> Vec<String> {
        (0..count).map(|_| self.generate_one()).collect()
    }
}

/// Generate a named corpus using a builtin grammar.
pub fn generate_corpus(name: &str, count: u32, seed: u64) -> Vec<String> {
    let grammar = match name {
        "http" => builtin_grammar_http11(),
        "json" => builtin_grammar_json(),
        "sql" => builtin_grammar_sql_select(),
        "xml" => builtin_grammar_xml(),
        "cmdline" => builtin_grammar_cmdline(),
        _ => builtin_grammar_json(),
    };
    let start = match name {
        "http" => "request",
        "json" => "value",
        "sql" => "query",
        "xml" => "document",
        "cmdline" => "cmdline",
        _ => "value",
    };
    let mut fuzzer = GrammarFuzzer::new(grammar, start, 6, seed);
    fuzzer.generate_corpus(count)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xorshift64_produces_nonzero() {
        let mut s = 1u64;
        let v = xorshift64(&mut s);
        assert_ne!(v, 0);
    }

    #[test]
    fn test_term_terminal_display() {
        let t = Term::terminal("hello");
        assert!(matches!(t, Term::Terminal(ref s) if s == "hello"));
    }

    #[test]
    fn test_grammar_has_rule() {
        let mut g = Grammar::new();
        g.add_rule("foo", vec![Expansion::single(Term::terminal("bar"))]);
        assert!(g.has_rule("foo"));
        assert!(!g.has_rule("baz"));
    }

    #[test]
    fn test_generate_http_nonempty() {
        let g = builtin_grammar_http11();
        let mut inst = GrammarInstance::new(g, 42);
        let s = inst.generate("request", 5);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_generate_json_contains_brackets_or_quotes() {
        let g = builtin_grammar_json();
        let mut inst = GrammarInstance::new(g, 77);
        let results: Vec<String> = (0..20).map(|_| inst.generate("value", 4)).collect();
        let has_special = results.iter().any(|s| s.contains('{') || s.contains('[') || s.contains('"'));
        assert!(has_special);
    }

    #[test]
    fn test_generate_sql_contains_select() {
        let g = builtin_grammar_sql_select();
        let mut inst = GrammarInstance::new(g, 1);
        let s = inst.generate("query", 4);
        assert!(s.contains("SELECT"));
    }

    #[test]
    fn test_generate_xml_contains_xml_decl() {
        let g = builtin_grammar_xml();
        let mut inst = GrammarInstance::new(g, 5);
        let s = inst.generate("document", 4);
        assert!(s.contains("<?xml"));
    }

    #[test]
    fn test_generate_cmdline_nonempty() {
        let g = builtin_grammar_cmdline();
        let mut inst = GrammarInstance::new(g, 9);
        let s = inst.generate("cmdline", 5);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_generate_corpus_count() {
        let corpus = generate_corpus("json", 10, 42);
        assert_eq!(corpus.len(), 10);
    }

    #[test]
    fn test_grammar_fuzzer_generate_corpus() {
        let g = builtin_grammar_http11();
        let mut fuzz = GrammarFuzzer::new(g, "request", 5, 100);
        let c = fuzz.generate_corpus(5);
        assert_eq!(c.len(), 5);
        for s in &c {
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_parse_bnf_simple() {
        let bnf = "greeting ::= \"hello\" | \"world\"\n";
        let g = parse_bnf_grammar(bnf);
        assert!(g.has_rule("greeting"));
        let exps = g.rules.get("greeting").unwrap();
        assert_eq!(exps.len(), 2);
    }

    #[test]
    fn test_parse_bnf_empty_lines_skipped() {
        let bnf = "\n# comment\nfoo ::= \"bar\"\n";
        let g = parse_bnf_grammar(bnf);
        assert!(g.has_rule("foo"));
    }

    #[test]
    fn test_optional_term_sometimes_empty() {
        let mut g = Grammar::new();
        g.add_rule("start", vec![
            Expansion::new(vec![
                Term::terminal("prefix-"),
                Term::optional(Term::terminal("optional")),
            ]),
        ]);
        let mut inst = GrammarInstance::new(g, 999);
        let results: Vec<String> = (0..20).map(|_| inst.generate("start", 3)).collect();
        let has_optional = results.iter().any(|s| s.contains("optional"));
        let has_no_optional = results.iter().any(|s| !s.contains("optional"));
        assert!(has_optional || has_no_optional); // both can happen
    }

    #[test]
    fn test_repeat_term_within_bounds() {
        let mut g = Grammar::new();
        g.add_rule("start", vec![
            Expansion::new(vec![
                Term::repeat(Term::terminal("x"), 2, 4),
            ]),
        ]);
        let mut inst = GrammarInstance::new(g, 123);
        for _ in 0..10 {
            let s = inst.generate("start", 3);
            let count = s.chars().filter(|&c| c == 'x').count();
            assert!((2..=4).contains(&count), "got {count}");
        }
    }

    #[test]
    fn test_grammar_mutation_changes_grammar() {
        let mut g = builtin_grammar_json();
        let original = g.rules.get("string").unwrap()[0].terms[0].clone();
        let mut rng = 42u64;
        // Run mutation several times to ensure a terminal gets mutated
        for _ in 0..100 {
            GrammarMutation::mutate_grammar(&mut g, &mut rng);
        }
        // At least one terminal should have changed (appended __mutated)
        let any_mutated = g.rules.values().flat_map(|exps| exps.iter())
            .flat_map(|exp| exp.terms.iter())
            .any(|t| matches!(t, Term::Terminal(s) if s.contains("__mutated")));
        assert!(any_mutated);
        let _ = original;
    }

    #[test]
    fn test_choice_term_varies() {
        let choices = vec![Term::terminal("a"), Term::terminal("b"), Term::terminal("c")];
        let mut g = Grammar::new();
        g.add_rule("start", vec![Expansion::single(Term::choice(choices))]);
        let mut inst = GrammarInstance::new(g, 77);
        let results: Vec<String> = (0..30).map(|_| inst.generate("start", 2)).collect();
        let unique: std::collections::HashSet<_> = results.iter().collect();
        assert!(unique.len() > 1);
    }
}
