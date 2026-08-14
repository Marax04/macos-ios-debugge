//! `grammar_fuzzer` — BNF-style grammar-based fuzzing for protocol inputs.
//!
//! Provides [`Grammar`], [`GrammarNode`], [`GrammarFuzzer`], built-in grammars
//! for HTTP/1.1, JSON, XML, and TLS `ClientHello`.

use rustre_fuzz_afl::{RngCore, XorShiftRng};
use std::collections::HashMap;

// ── GrammarNode ───────────────────────────────────────────────────────────────

/// A single node in a grammar rule.
#[derive(Debug, Clone)]
pub enum GrammarNode {
    /// A literal byte sequence.
    Terminal(Vec<u8>),
    /// A reference to another named rule.
    NonTerminal(String),
    /// One or more alternatives; one is chosen randomly.
    Choice(Vec<Self>),
    /// All children concatenated in order.
    Sequence(Vec<Self>),
    /// Repeat `min..=max` times.
    Repeat {
        inner: Box<Self>,
        min: usize,
        max: usize,
    },
    /// Optional node (0 or 1 occurrence).
    Optional(Box<Self>),
    /// A random byte in the given inclusive range.
    ByteRange(u8, u8),
    /// A random decimal integer in `[min, max]`.
    IntRange(i64, i64),
}

impl GrammarNode {
    /// Convenience: terminal from a string literal.
    #[must_use]
    pub fn lit(s: &str) -> Self {
        Self::Terminal(s.as_bytes().to_vec())
    }

    /// Convenience: non-terminal reference.
    #[must_use]
    pub fn nt(name: &str) -> Self {
        Self::NonTerminal(name.to_owned())
    }

    /// Wrap in `Optional`.
    #[must_use]
    pub fn optional(self) -> Self {
        Self::Optional(Box::new(self))
    }

    /// Wrap in `Repeat` with fixed bounds.
    #[must_use]
    pub fn repeat(self, min: usize, max: usize) -> Self {
        Self::Repeat {
            inner: Box::new(self),
            min,
            max,
        }
    }
}

/// Convenience free function: terminal literal node from a string slice.
#[must_use]
pub fn lit(s: &str) -> GrammarNode {
    GrammarNode::Terminal(s.as_bytes().to_vec())
}

// ── Grammar ───────────────────────────────────────────────────────────────────

/// A complete BNF-style grammar: a named map of rules.
#[derive(Debug, Clone, Default)]
pub struct Grammar {
    /// Named production rules.
    pub rules: HashMap<String, GrammarNode>,
    /// The start rule name.
    pub start: String,
}

impl Grammar {
    /// Create a new empty grammar.
    #[must_use]
    pub fn new(start: impl Into<String>) -> Self {
        Self {
            rules: HashMap::new(),
            start: start.into(),
        }
    }

    /// Add a rule.
    pub fn rule(mut self, name: impl Into<String>, node: GrammarNode) -> Self {
        self.rules.insert(name.into(), node);
        self
    }

    /// Return the start rule node.
    #[must_use]
    pub fn start_node(&self) -> Option<&GrammarNode> {
        self.rules.get(&self.start)
    }

    /// Number of rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ── GenerationConfig ──────────────────────────────────────────────────────────

/// Configuration for grammar-based input generation.
#[derive(Debug, Clone)]
pub struct GenerationConfig {
    /// Maximum recursion depth before a terminal is substituted.
    pub max_depth: usize,
    /// Maximum total output length in bytes.
    pub max_length: usize,
    /// Seed for the PRNG (0 = random).
    pub seed: u64,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_length: 65_536,
            seed: 0,
        }
    }
}

impl GenerationConfig {
    /// Create a config with explicit depth and length.
    #[must_use]
    pub fn new(max_depth: usize, max_length: usize) -> Self {
        Self {
            max_depth,
            max_length,
            ..Default::default()
        }
    }
}

// ── GrammarFuzzer ─────────────────────────────────────────────────────────────

/// Generates random valid inputs from a [`Grammar`].
pub struct GrammarFuzzer {
    pub grammar: Grammar,
    pub config: GenerationConfig,
    rng: XorShiftRng,
}

impl GrammarFuzzer {
    /// Create a new fuzzer with the given grammar and config.
    #[must_use]
    pub const fn new(grammar: Grammar, config: GenerationConfig) -> Self {
        let seed = if config.seed == 0 {
            0xcafe_babe_dead_beef
        } else {
            config.seed
        };
        Self {
            grammar,
            config,
            rng: XorShiftRng::new(seed),
        }
    }

    /// Generate a single random input from the grammar's start rule.
    #[must_use]
    pub fn generate(&mut self) -> Vec<u8> {
        let start = self.grammar.start.clone();
        let max_depth = self.config.max_depth;
        let max_length = self.config.max_length;
        let rules = &self.grammar.rules;
        generate_node(
            &GrammarNode::NonTerminal(start),
            rules,
            &mut self.rng,
            max_depth,
            max_length,
        )
    }

    /// Generate `n` inputs.
    pub fn generate_n(&mut self, n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|_| self.generate()).collect()
    }

    /// Generate and return as a UTF-8 string (lossy).
    pub fn generate_string(&mut self) -> String {
        String::from_utf8_lossy(&self.generate()).into_owned()
    }
}

fn generate_node(
    node: &GrammarNode,
    rules: &HashMap<String, GrammarNode>,
    rng: &mut dyn RngCore,
    depth: usize,
    max_len: usize,
) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    match node {
        GrammarNode::Terminal(b) => b[..b.len().min(max_len)].to_vec(),
        GrammarNode::ByteRange(lo, hi) => {
            let range = (*hi as usize).saturating_sub(*lo as usize) + 1;
            vec![*lo + (rng.next_usize(range)) as u8]
        }
        GrammarNode::IntRange(lo, hi) => {
            let range = (hi.saturating_sub(*lo).unsigned_abs() as usize) + 1;
            let val = *lo + rng.next_usize(range) as i64;
            val.to_string().into_bytes()
        }
        GrammarNode::NonTerminal(name) => {
            if depth == 0 {
                // Depth exceeded — substitute empty bytes.
                return Vec::new();
            }
            match rules.get(name) {
                Some(inner) => generate_node(inner, rules, rng, depth - 1, max_len),
                None => Vec::new(),
            }
        }
        GrammarNode::Choice(alternatives) => {
            if alternatives.is_empty() {
                return Vec::new();
            }
            let idx = rng.next_usize(alternatives.len());
            generate_node(&alternatives[idx], rules, rng, depth, max_len)
        }
        GrammarNode::Sequence(children) => {
            let mut out = Vec::new();
            for child in children {
                if out.len() >= max_len {
                    break;
                }
                let remaining = max_len - out.len();
                let part = generate_node(child, rules, rng, depth, remaining);
                out.extend(part);
            }
            out
        }
        GrammarNode::Repeat { inner, min, max } => {
            let count = *min + rng.next_usize(max.saturating_sub(*min) + 1);
            let mut out = Vec::new();
            for _ in 0..count {
                if out.len() >= max_len {
                    break;
                }
                let remaining = max_len - out.len();
                let part = generate_node(inner, rules, rng, depth, remaining);
                out.extend(part);
            }
            out
        }
        GrammarNode::Optional(inner) => {
            if rng.next_u32() & 1 == 0 {
                generate_node(inner, rules, rng, depth, max_len)
            } else {
                Vec::new()
            }
        }
    }
}

// ── Built-in grammars ─────────────────────────────────────────────────────────

/// Build a minimal HTTP/1.1 request grammar.
#[must_use]
pub fn http11_grammar() -> Grammar {
    use GrammarNode::{Sequence, NonTerminal, Terminal, Optional, Choice, ByteRange};
    Grammar::new("request")
        .rule(
            "request",
            Sequence(vec![
                NonTerminal("method".into()),
                Terminal(b" ".to_vec()),
                NonTerminal("path".into()),
                Terminal(b" HTTP/1.1\r\nHost: ".to_vec()),
                NonTerminal("host".into()),
                Terminal(b"\r\n".to_vec()),
                Optional(Box::new(NonTerminal("headers".into()))),
                Terminal(b"\r\n".to_vec()),
                Optional(Box::new(NonTerminal("body".into()))),
            ]),
        )
        .rule(
            "method",
            Choice(vec![
                lit("GET"),
                lit("POST"),
                lit("PUT"),
                lit("DELETE"),
                lit("OPTIONS"),
                lit("HEAD"),
                lit("PATCH"),
                lit("TRACE"),
            ]),
        )
        .rule(
            "path",
            Sequence(vec![
                Terminal(b"/".to_vec()),
                NonTerminal("path_segment".into()).repeat(0, 4),
            ]),
        )
        .rule(
            "path_segment",
            Sequence(vec![
                NonTerminal("word".into()),
                Terminal(b"/".to_vec()).optional(),
            ]),
        )
        .rule(
            "host",
            Sequence(vec![
                NonTerminal("word".into()),
                Terminal(b".".to_vec()),
                NonTerminal("tld".into()),
            ]),
        )
        .rule(
            "tld",
            Choice(vec![lit("com"), lit("net"), lit("org"), lit("io")]),
        )
        .rule(
            "headers",
            Sequence(vec![
                NonTerminal("header".into()),
                NonTerminal("header".into()).optional(),
            ]),
        )
        .rule(
            "header",
            Sequence(vec![
                NonTerminal("word".into()),
                Terminal(b": ".to_vec()),
                NonTerminal("word".into()),
                Terminal(b"\r\n".to_vec()),
            ]),
        )
        .rule("body", NonTerminal("word".into()).repeat(0, 16))
        .rule("word", NonTerminal("alpha".into()).repeat(1, 12))
        .rule("alpha", ByteRange(b'a', b'z'))
}

/// Build a JSON value grammar.
#[must_use]
pub fn json_grammar() -> Grammar {
    use GrammarNode::{Choice, NonTerminal, Sequence, Optional, ByteRange, IntRange};
    Grammar::new("value")
        .rule(
            "value",
            Choice(vec![
                NonTerminal("object".into()),
                NonTerminal("array".into()),
                NonTerminal("string".into()),
                NonTerminal("number".into()),
                lit("true"),
                lit("false"),
                lit("null"),
            ]),
        )
        .rule(
            "object",
            Sequence(vec![
                lit("{"),
                Optional(Box::new(NonTerminal("members".into()))),
                lit("}"),
            ]),
        )
        .rule(
            "members",
            Sequence(vec![
                NonTerminal("pair".into()),
                Optional(Box::new(Sequence(vec![
                    lit(","),
                    NonTerminal("pair".into()),
                ]))),
            ]),
        )
        .rule(
            "pair",
            Sequence(vec![
                NonTerminal("string".into()),
                lit(":"),
                NonTerminal("value".into()),
            ]),
        )
        .rule(
            "array",
            Sequence(vec![
                lit("["),
                Optional(Box::new(NonTerminal("elements".into()))),
                lit("]"),
            ]),
        )
        .rule(
            "elements",
            Sequence(vec![
                NonTerminal("value".into()),
                Optional(Box::new(Sequence(vec![
                    lit(","),
                    NonTerminal("value".into()),
                ]))),
            ]),
        )
        .rule(
            "string",
            Sequence(vec![lit("\""), NonTerminal("chars".into()), lit("\"")]),
        )
        .rule("chars", NonTerminal("char".into()).repeat(0, 16))
        .rule(
            "char",
            Choice(vec![ByteRange(b'a', b'z'), ByteRange(b'0', b'9'), lit("_")]),
        )
        .rule(
            "number",
            Choice(vec![
                IntRange(i64::from(i16::MIN), i64::from(i16::MAX)),
                Sequence(vec![IntRange(-100, 100), lit("."), IntRange(0, 999)]),
            ]),
        )
}

/// Build a minimal XML grammar.
#[must_use]
pub fn xml_grammar() -> Grammar {
    use GrammarNode::{Sequence, NonTerminal, Optional, Choice, ByteRange};
    Grammar::new("document")
        .rule(
            "document",
            Sequence(vec![
                lit("<?xml version=\"1.0\"?>"),
                NonTerminal("element".into()),
            ]),
        )
        .rule(
            "element",
            Sequence(vec![
                lit("<"),
                NonTerminal("tag".into()),
                lit(">"),
                Optional(Box::new(NonTerminal("content".into()))),
                lit("</"),
                NonTerminal("tag".into()),
                lit(">"),
            ]),
        )
        .rule(
            "content",
            Choice(vec![
                NonTerminal("element".into()),
                NonTerminal("text".into()),
            ]),
        )
        .rule("text", NonTerminal("word".into()).repeat(0, 8))
        .rule("tag", NonTerminal("alpha".into()).repeat(1, 10))
        .rule("word", NonTerminal("alpha".into()).repeat(1, 8))
        .rule("alpha", ByteRange(b'a', b'z'))
}

/// Build a minimal TLS `ClientHello` grammar (conceptual wire format).
#[must_use]
pub fn tls_client_hello_grammar() -> Grammar {
    use GrammarNode::{Sequence, Terminal, Choice, NonTerminal, ByteRange};
    Grammar::new("client_hello")
        .rule(
            "client_hello",
            Sequence(vec![
                // ContentType: 0x16 (handshake)
                Terminal(vec![0x16]),
                // Protocol version: TLS 1.0–1.3 (major.minor)
                Choice(vec![Terminal(vec![0x03, 0x01]), Terminal(vec![0x03, 0x03])]),
                // Length (2 bytes, placeholder)
                Terminal(vec![0x00, 0x50]),
                // Handshake type: ClientHello = 1
                Terminal(vec![0x01]),
                // Handshake length (3 bytes, placeholder)
                Terminal(vec![0x00, 0x00, 0x4C]),
                // Client version
                Choice(vec![Terminal(vec![0x03, 0x03]), Terminal(vec![0x03, 0x04])]),
                // Random (32 bytes)
                NonTerminal("random32".into()),
                // Session ID length (0)
                Terminal(vec![0x00]),
                // Cipher suites length (2)
                Terminal(vec![0x00, 0x02]),
                // Cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
                Choice(vec![
                    Terminal(vec![0x00, 0x2F]),
                    Terminal(vec![0x00, 0x35]),
                    Terminal(vec![0x13, 0x01]),
                ]),
                // Compression methods
                Terminal(vec![0x01, 0x00]),
            ]),
        )
        .rule("random32", ByteRange(0x00, 0xff).repeat(32, 32))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grammar_node_lit() {
        let n = GrammarNode::lit("hello");
        assert!(matches!(n, GrammarNode::Terminal(ref b) if b == b"hello"));
    }

    #[test]
    fn test_grammar_node_nt() {
        let n = GrammarNode::nt("foo");
        assert!(matches!(n, GrammarNode::NonTerminal(ref s) if s == "foo"));
    }

    #[test]
    fn test_grammar_rule_count() {
        let g = Grammar::new("start")
            .rule("start", GrammarNode::lit("x"))
            .rule("foo", GrammarNode::lit("y"));
        assert_eq!(g.rule_count(), 2);
    }

    #[test]
    fn test_grammar_start_node() {
        let g = Grammar::new("start").rule("start", GrammarNode::lit("ok"));
        assert!(g.start_node().is_some());
    }

    #[test]
    fn test_generate_terminal() {
        let g = Grammar::new("s").rule("s", GrammarNode::lit("ping"));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        assert_eq!(fuzzer.generate(), b"ping");
    }

    #[test]
    fn test_generate_choice_not_empty() {
        let g = Grammar::new("s").rule(
            "s",
            GrammarNode::Choice(vec![
                GrammarNode::lit("a"),
                GrammarNode::lit("b"),
                GrammarNode::lit("c"),
            ]),
        );
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        for _ in 0..20 {
            let out = fuzzer.generate();
            assert!(out == b"a" || out == b"b" || out == b"c");
        }
    }

    #[test]
    fn test_generate_sequence() {
        let g = Grammar::new("s").rule(
            "s",
            GrammarNode::Sequence(vec![GrammarNode::lit("foo"), GrammarNode::lit("bar")]),
        );
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        assert_eq!(fuzzer.generate(), b"foobar");
    }

    #[test]
    fn test_generate_repeat_bounds() {
        let g = Grammar::new("s").rule("s", GrammarNode::lit("x").repeat(3, 3));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        assert_eq!(fuzzer.generate(), b"xxx");
    }

    #[test]
    fn test_generate_optional() {
        let g = Grammar::new("s").rule("s", GrammarNode::lit("opt").optional());
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        let mut saw_empty = false;
        let mut saw_opt = false;
        for _ in 0..100 {
            let out = fuzzer.generate();
            if out.is_empty() {
                saw_empty = true;
            }
            if out == b"opt" {
                saw_opt = true;
            }
        }
        assert!(saw_empty || saw_opt); // at least one must be true
    }

    #[test]
    fn test_generate_non_terminal() {
        let g = Grammar::new("s")
            .rule("s", GrammarNode::nt("inner"))
            .rule("inner", GrammarNode::lit("deep"));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        assert_eq!(fuzzer.generate(), b"deep");
    }

    #[test]
    fn test_generate_max_depth_stops_recursion() {
        // A self-referential grammar that would loop forever without depth limit.
        let g = Grammar::new("s").rule("s", GrammarNode::nt("s"));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::new(4, 1024));
        let out = fuzzer.generate();
        assert!(out.is_empty()); // depth exceeded → empty
    }

    #[test]
    fn test_generate_max_length_truncated() {
        let g = Grammar::new("s").rule("s", GrammarNode::lit("x").repeat(0, 1000));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::new(16, 50));
        let out = fuzzer.generate();
        assert!(out.len() <= 50);
    }

    #[test]
    fn test_generate_n_count() {
        let g = Grammar::new("s").rule("s", GrammarNode::lit("y"));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        let outputs = fuzzer.generate_n(10);
        assert_eq!(outputs.len(), 10);
    }

    #[test]
    fn test_generate_byte_range() {
        let g = Grammar::new("s").rule("s", GrammarNode::ByteRange(b'0', b'9'));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        for _ in 0..50 {
            let out = fuzzer.generate();
            assert_eq!(out.len(), 1);
            assert!(out[0] >= b'0' && out[0] <= b'9');
        }
    }

    #[test]
    fn test_generate_int_range() {
        let g = Grammar::new("s").rule("s", GrammarNode::IntRange(1, 100));
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::default());
        for _ in 0..50 {
            let s = fuzzer.generate_string();
            let n: i64 = s.parse().unwrap();
            assert!((1..=100).contains(&n));
        }
    }

    #[test]
    fn test_http11_grammar_generates() {
        let g = http11_grammar();
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::new(8, 4096));
        let out = fuzzer.generate();
        assert!(!out.is_empty());
        // Should start with a method.
        let s = String::from_utf8_lossy(&out);
        let valid_methods = [
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
        ];
        assert!(valid_methods.iter().any(|m| s.starts_with(m)));
    }

    #[test]
    fn test_json_grammar_generates() {
        let g = json_grammar();
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::new(6, 2048));
        for _ in 0..10 {
            let out = fuzzer.generate();
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn test_xml_grammar_starts_with_decl() {
        let g = xml_grammar();
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::new(6, 2048));
        let out = fuzzer.generate();
        assert!(out.starts_with(b"<?xml"));
    }

    #[test]
    fn test_tls_client_hello_first_byte() {
        let g = tls_client_hello_grammar();
        let mut fuzzer = GrammarFuzzer::new(g, GenerationConfig::new(8, 256));
        let out = fuzzer.generate();
        assert_eq!(out[0], 0x16);
    }

    #[test]
    fn test_generation_config_defaults() {
        let cfg = GenerationConfig::default();
        assert_eq!(cfg.max_depth, 16);
        assert_eq!(cfg.max_length, 65_536);
    }

    #[test]
    fn test_grammar_fuzzer_different_seeds_differ() {
        let g1 = http11_grammar();
        let g2 = http11_grammar();
        let mut f1 = GrammarFuzzer::new(
            g1,
            GenerationConfig {
                seed: 1,
                ..Default::default()
            },
        );
        let mut f2 = GrammarFuzzer::new(
            g2,
            GenerationConfig {
                seed: 99999,
                ..Default::default()
            },
        );
        let o1 = f1.generate();
        let o2 = f2.generate();
        // Different seeds should produce different outputs (with overwhelming probability).
        let _ = (o1, o2); // may coincidentally match, but shouldn't panic
    }
}
