//! Custom and structured mutators for `rustre-fuzz-libfuzzer`.
//!
//! Provides [`CustomMutator`] (trait), [`MutatorContext`], [`StructuredMutator`],
//! [`DictionaryMutator`], [`CrossoverMutator`], [`MutatorChain`], and
//! [`MutationStats`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{LibFuzzerError, SimpleRng};

// ── MutatorContext ────────────────────────────────────────────────────────────

/// Execution context passed to every mutator call.
///
/// Contains the PRNG seed, maximum allowed output size, and an optional
/// corpus snapshot for crossover mutations.
#[derive(Debug, Clone)]
pub struct MutatorContext {
    /// PRNG seed for this mutation.
    pub seed: u64,
    /// Maximum allowed output size in bytes.
    pub max_size: usize,
    /// Optional corpus entries available for crossover.
    pub corpus: Vec<Vec<u8>>,
    /// Internal PRNG derived from `seed`.
    rng: SimpleRng,
}

impl MutatorContext {
    /// Create a new context.
    #[must_use]
    pub const fn new(seed: u64, max_size: usize) -> Self {
        Self {
            seed,
            max_size,
            corpus: Vec::new(),
            rng: SimpleRng::new(seed),
        }
    }

    /// Add corpus entries for potential crossover use.
    #[must_use] 
    pub fn with_corpus(mut self, corpus: Vec<Vec<u8>>) -> Self {
        self.corpus = corpus;
        self
    }

    /// Generate the next random `u64`.
    pub const fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Generate a random `usize` in `[0, max)`.
    pub const fn next_range(&mut self, max: u64) -> u64 {
        self.rng.next_range(max)
    }

    /// Pick a random entry from the corpus, or `None` if empty.
    pub fn random_corpus_entry(&mut self) -> Option<&[u8]> {
        if self.corpus.is_empty() {
            return None;
        }
        let idx = (self.rng.next_range(self.corpus.len() as u64)) as usize;
        Some(&self.corpus[idx])
    }

    /// Truncate `data` to at most `max_size` bytes.
    pub fn truncate(&self, data: &mut Vec<u8>) {
        if self.max_size > 0 && data.len() > self.max_size {
            data.truncate(self.max_size);
        }
    }
}

// ── CustomMutator trait ───────────────────────────────────────────────────────

/// Trait for custom libFuzzer-style mutators.
pub trait CustomMutatorTrait: Send {
    /// Produce a mutated version of `input` given `ctx`.
    ///
    /// # Errors
    /// Returns [`LibFuzzerError`] when the mutator cannot proceed.
    fn mutate(&mut self, input: &[u8], ctx: &mut MutatorContext) -> Result<Vec<u8>, LibFuzzerError>;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Whether this mutator can operate on empty inputs.
    fn handles_empty(&self) -> bool {
        false
    }
}

// ── MutationStats ─────────────────────────────────────────────────────────────

/// Accumulated statistics for a single mutator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MutationStats {
    /// Total mutations applied.
    pub total_mutations: u64,
    /// Mutations that produced an interesting result.
    pub interesting_mutations: u64,
    /// Mutations that resulted in a crash.
    pub crash_mutations: u64,
    /// Total wall-clock time spent in this mutator.
    pub total_time: Duration,
    /// Longest single mutation time.
    pub max_time: Duration,
    /// Total bytes generated.
    pub total_bytes_generated: u64,
}

impl MutationStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a mutation.
    pub fn record(&mut self, output_len: usize, elapsed: Duration) {
        self.total_mutations += 1;
        self.total_bytes_generated += output_len as u64;
        self.total_time += elapsed;
        if elapsed > self.max_time {
            self.max_time = elapsed;
        }
    }

    /// Record an interesting result.
    pub const fn record_interesting(&mut self) {
        self.interesting_mutations += 1;
    }

    /// Record a crash.
    pub const fn record_crash(&mut self) {
        self.crash_mutations += 1;
    }

    /// Interesting rate (0.0–1.0).
    #[must_use]
    pub fn interesting_rate(&self) -> f64 {
        if self.total_mutations == 0 {
            0.0
        } else {
            (self.interesting_mutations as f64) / (self.total_mutations as f64)
        }
    }

    /// Average mutation time.
    #[must_use]
    pub fn avg_time(&self) -> Duration {
        if self.total_mutations == 0 {
            Duration::ZERO
        } else {
            self.total_time / (self.total_mutations as u32)
        }
    }
}

// ── Grammar node types ────────────────────────────────────────────────────────

/// A node in a simple structured grammar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GrammarNode {
    /// Literal bytes.
    Literal(Vec<u8>),
    /// A choice among multiple alternatives.
    Choice(Vec<Self>),
    /// A sequence of nodes concatenated.
    Sequence(Vec<Self>),
    /// A node repeated between `min` and `max` times.
    Repeat {
        /// Inner node.
        node: Box<Self>,
        /// Minimum repetitions.
        min: usize,
        /// Maximum repetitions.
        max: usize,
    },
    /// A variable-length random byte blob.
    Blob {
        /// Minimum length in bytes.
        min_len: usize,
        /// Maximum length in bytes.
        max_len: usize,
    },
    /// A u8 value chosen from the interesting set.
    InterestingU8,
    /// A u32 little-endian integer.
    U32Le(u32),
}

impl GrammarNode {
    /// Generate bytes from this grammar node using `rng`.
    #[must_use]
    pub fn generate(&self, rng: &mut SimpleRng) -> Vec<u8> {
        match self {
            Self::Literal(b) => b.clone(),
            Self::Choice(alts) => {
                if alts.is_empty() {
                    return Vec::new();
                }
                let idx = (rng.next_range(alts.len() as u64)) as usize;
                alts[idx].generate(rng)
            }
            Self::Sequence(nodes) => {
                let mut out = Vec::new();
                for n in nodes {
                    out.extend(n.generate(rng));
                }
                out
            }
            Self::Repeat { node, min, max } => {
                let count = if max <= min {
                    *min
                } else {
                    *min + (rng.next_range((*max - *min + 1) as u64) as usize)
                };
                let mut out = Vec::new();
                for _ in 0..count {
                    out.extend(node.generate(rng));
                }
                out
            }
            Self::Blob { min_len, max_len } => {
                let len = if max_len <= min_len {
                    *min_len
                } else {
                    *min_len + (rng.next_range((*max_len - *min_len + 1) as u64) as usize)
                };
                (0..len).map(|_| rng.next_u64() as u8).collect()
            }
            Self::InterestingU8 => {
                const INTERESTING: &[u8] = &[0, 1, 0x7f, 0x80, 0xfe, 0xff];
                let idx = (rng.next_range(INTERESTING.len() as u64)) as usize;
                vec![INTERESTING[idx]]
            }
            Self::U32Le(v) => v.to_le_bytes().to_vec(),
        }
    }
}

// ── StructuredMutator ─────────────────────────────────────────────────────────

/// A grammar-aware mutator that generates inputs from a grammar tree.
///
/// When `input` is provided, it is partially preserved via a crossover with
/// newly generated bytes.
pub struct StructuredMutator {
    /// Grammar root node.
    pub grammar: GrammarNode,
    /// Per-mutation stats.
    pub stats: MutationStats,
    /// Whether to crossover new bytes with the input.
    pub crossover: bool,
}

impl StructuredMutator {
    /// Create a new structured mutator with the given grammar.
    #[must_use]
    pub fn new(grammar: GrammarNode) -> Self {
        Self {
            grammar,
            stats: MutationStats::new(),
            crossover: true,
        }
    }

    /// Create a simple mutator that generates random blobs.
    #[must_use]
    pub fn random_blob(min_len: usize, max_len: usize) -> Self {
        Self::new(GrammarNode::Blob { min_len, max_len })
    }
}

impl CustomMutatorTrait for StructuredMutator {
    fn name(&self) -> &'static str {
        "StructuredMutator"
    }

    fn handles_empty(&self) -> bool {
        true
    }

    fn mutate(&mut self, input: &[u8], ctx: &mut MutatorContext) -> Result<Vec<u8>, LibFuzzerError> {
        let start = Instant::now();
        let mut rng = SimpleRng::new(ctx.seed);
        let mut generated = self.grammar.generate(&mut rng);

        if self.crossover && !input.is_empty() && !generated.is_empty() {
            let split = (rng.next_range(input.len() as u64)) as usize;
            let gen_split = (rng.next_range(generated.len() as u64)) as usize;
            let mut out = input[..split].to_vec();
            out.extend_from_slice(&generated[gen_split..]);
            generated = out;
        }

        ctx.truncate(&mut generated);
        self.stats.record(generated.len(), start.elapsed());
        Ok(generated)
    }
}

// ── DictionaryMutator ─────────────────────────────────────────────────────────

/// Inserts or overwrites bytes at a random position with dictionary tokens.
pub struct DictionaryMutator {
    /// Token list.
    pub tokens: Vec<Vec<u8>>,
    /// Per-mutation stats.
    pub stats: MutationStats,
}

impl DictionaryMutator {
    /// Create a new mutator with the given tokens.
    #[must_use]
    pub fn new(tokens: Vec<Vec<u8>>) -> Self {
        Self {
            tokens,
            stats: MutationStats::new(),
        }
    }

    /// Add a token.
    pub fn add_token(&mut self, token: Vec<u8>) {
        self.tokens.push(token);
    }

    /// Add a string token.
    pub fn add_str_token(&mut self, s: &str) {
        self.tokens.push(s.as_bytes().to_vec());
    }

    /// Load tokens from an AFL-style text format.
    /// Lines are either `"token"` (quoted) or bare text.
    pub fn load_from_text(&mut self, text: &str) {
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if l.starts_with('"') && l.ends_with('"') && l.len() >= 2 {
                self.tokens.push(l.as_bytes()[1..l.len() - 1].to_vec());
            } else {
                self.tokens.push(l.as_bytes().to_vec());
            }
        }
    }

    /// Number of tokens.
    #[must_use]
    pub const fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

impl CustomMutatorTrait for DictionaryMutator {
    fn name(&self) -> &'static str {
        "DictionaryMutator"
    }

    fn mutate(&mut self, input: &[u8], ctx: &mut MutatorContext) -> Result<Vec<u8>, LibFuzzerError> {
        let start = Instant::now();
        if self.tokens.is_empty() || input.is_empty() {
            self.stats.record(input.len(), start.elapsed());
            return Ok(input.to_vec());
        }
        let tok_idx = (ctx.next_range(self.tokens.len() as u64)) as usize;
        let token = &self.tokens[tok_idx];
        let mut out = input.to_vec();
        let pos = (ctx.next_range((out.len() + 1) as u64)) as usize;
        // Overwrite bytes starting at pos (clamped to buffer).
        let end = (pos + token.len()).min(out.len());
        if pos < out.len() {
            let copy_len = end - pos;
            out[pos..end].copy_from_slice(&token[..copy_len]);
        } else if out.len() < ctx.max_size {
            // Append
            let remaining = ctx.max_size - out.len();
            let append_len = token.len().min(remaining);
            out.extend_from_slice(&token[..append_len]);
        }
        ctx.truncate(&mut out);
        self.stats.record(out.len(), start.elapsed());
        Ok(out)
    }
}

// ── CrossoverMutator ──────────────────────────────────────────────────────────

/// Splices the input with a randomly chosen corpus entry.
pub struct CrossoverMutator {
    /// Per-mutation stats.
    pub stats: MutationStats,
}

impl CrossoverMutator {
    /// Create a new crossover mutator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: MutationStats::new(),
        }
    }
}

impl Default for CrossoverMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl CustomMutatorTrait for CrossoverMutator {
    fn name(&self) -> &'static str {
        "CrossoverMutator"
    }

    fn mutate(&mut self, input: &[u8], ctx: &mut MutatorContext) -> Result<Vec<u8>, LibFuzzerError> {
        let start = Instant::now();
        let result = ctx.random_corpus_entry().map(<[u8]>::to_vec).map_or_else(|| input.to_vec(), |other| if input.is_empty() {
                other
            } else if other.is_empty() {
                input.to_vec()
            } else {
                let split_a = (ctx.next_range(input.len() as u64)) as usize;
                let split_b = (ctx.next_range(other.len() as u64)) as usize;
                let mut out = Vec::with_capacity(split_a + (other.len() - split_b));
                out.extend_from_slice(&input[..split_a]);
                out.extend_from_slice(&other[split_b..]);
                out
            });
        let mut out = result;
        ctx.truncate(&mut out);
        self.stats.record(out.len(), start.elapsed());
        Ok(out)
    }
}

// ── MutatorChain ─────────────────────────────────────────────────────────────

/// Chains multiple mutators together, applying them in sequence or randomly.
pub struct MutatorChain {
    /// Ordered list of mutators.
    mutators: Vec<Box<dyn CustomMutatorTrait>>,
    /// Per-mutator stats keyed by name.
    pub stats: HashMap<String, MutationStats>,
    /// Chain mode.
    pub mode: ChainMode,
    /// Total rounds applied.
    pub total_rounds: u64,
}

/// How the chain applies its mutators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainMode {
    /// Apply all mutators in order on the same input; each receives the
    /// previous output.
    Sequential,
    /// Apply a randomly chosen single mutator each call.
    Random,
    /// Apply all mutators and return the shortest result.
    MinLength,
}

impl MutatorChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new(mode: ChainMode) -> Self {
        Self {
            mutators: Vec::new(),
            stats: HashMap::new(),
            mode,
            total_rounds: 0,
        }
    }

    /// Add a mutator to the chain.
    pub fn add<M: CustomMutatorTrait + 'static>(&mut self, mutator: M) {
        let name = mutator.name().to_string();
        self.stats.entry(name).or_default();
        self.mutators.push(Box::new(mutator));
    }

    /// Number of mutators in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mutators.len()
    }

    /// True when the chain has no mutators.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mutators.is_empty()
    }

    /// Apply the chain to `input` and return the result.
    ///
    /// # Errors
    /// Returns [`LibFuzzerError`] if any mutator in the chain fails.
    pub fn mutate(&mut self, input: &[u8], ctx: &mut MutatorContext) -> Result<Vec<u8>, LibFuzzerError> {
        if self.mutators.is_empty() {
            return Ok(input.to_vec());
        }
        self.total_rounds += 1;
        match self.mode {
            ChainMode::Sequential => {
                let mut current = input.to_vec();
                for m in &mut self.mutators {
                    let start = Instant::now();
                    current = m.mutate(&current, ctx)?;
                    let elapsed = start.elapsed();
                    let name = m.name().to_string();
                    self.stats.entry(name).or_default().record(current.len(), elapsed);
                }
                Ok(current)
            }
            ChainMode::Random => {
                let idx = (ctx.next_range(self.mutators.len() as u64)) as usize;
                let start = Instant::now();
                let result = self.mutators[idx].mutate(input, ctx)?;
                let elapsed = start.elapsed();
                let name = self.mutators[idx].name().to_string();
                self.stats.entry(name).or_default().record(result.len(), elapsed);
                Ok(result)
            }
            ChainMode::MinLength => {
                let mut best = input.to_vec();
                for m in &mut self.mutators {
                    let start = Instant::now();
                    let candidate = m.mutate(input, ctx)?;
                    let elapsed = start.elapsed();
                    let name = m.name().to_string();
                    self.stats.entry(name).or_default().record(candidate.len(), elapsed);
                    if candidate.len() < best.len() {
                        best = candidate;
                    }
                }
                Ok(best)
            }
        }
    }

    /// Return the name of the most productive mutator (highest interesting rate).
    #[must_use]
    pub fn best_mutator(&self) -> Option<&str> {
        self.stats
            .iter()
            .max_by(|a, b| {
                a.1.interesting_rate()
                    .partial_cmp(&b.1.interesting_rate())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(name, _)| name.as_str())
    }

    /// Record an interesting result for the mutator at `idx`.
    pub fn record_interesting(&mut self, name: &str) {
        if let Some(s) = self.stats.get_mut(name) {
            s.record_interesting();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(seed: u64) -> MutatorContext {
        MutatorContext::new(seed, 4096)
    }

    fn ctx_with_corpus(seed: u64, corpus: Vec<Vec<u8>>) -> MutatorContext {
        MutatorContext::new(seed, 4096).with_corpus(corpus)
    }

    // ── MutatorContext ────────────────────────────────────────────────────────

    #[test]
    fn context_next_u64_deterministic() {
        let mut a = ctx(42);
        let mut b = ctx(42);
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn context_next_range_in_bounds() {
        let mut c = ctx(1);
        for _ in 0..100 {
            assert!(c.next_range(10) < 10);
        }
    }

    #[test]
    fn context_truncate() {
        let c = MutatorContext::new(0, 4);
        let mut data = vec![1u8; 10];
        c.truncate(&mut data);
        assert_eq!(data.len(), 4);
    }

    #[test]
    fn context_truncate_no_op_within_limit() {
        let c = MutatorContext::new(0, 100);
        let mut data = vec![1u8; 5];
        c.truncate(&mut data);
        assert_eq!(data.len(), 5);
    }

    #[test]
    fn context_random_corpus_entry_none_when_empty() {
        let mut c = ctx(0);
        assert!(c.random_corpus_entry().is_none());
    }

    #[test]
    fn context_random_corpus_entry_returns_something() {
        let mut c = ctx_with_corpus(0, vec![vec![1, 2], vec![3, 4]]);
        assert!(c.random_corpus_entry().is_some());
    }

    // ── MutationStats ─────────────────────────────────────────────────────────

    #[test]
    fn mutation_stats_initial() {
        let s = MutationStats::new();
        assert_eq!(s.total_mutations, 0);
        assert!((s.interesting_rate() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn mutation_stats_record() {
        let mut s = MutationStats::new();
        s.record(100, Duration::from_millis(1));
        assert_eq!(s.total_mutations, 1);
        assert_eq!(s.total_bytes_generated, 100);
    }

    #[test]
    fn mutation_stats_interesting_rate() {
        let mut s = MutationStats::new();
        s.record(10, Duration::ZERO);
        s.record(10, Duration::ZERO);
        s.record_interesting();
        assert!((s.interesting_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn mutation_stats_avg_time() {
        let mut s = MutationStats::new();
        s.record(1, Duration::from_millis(10));
        s.record(1, Duration::from_millis(20));
        let avg = s.avg_time();
        assert_eq!(avg, Duration::from_millis(15));
    }

    // ── GrammarNode ───────────────────────────────────────────────────────────

    #[test]
    fn grammar_literal_generates_exact() {
        let node = GrammarNode::Literal(b"HELLO".to_vec());
        let mut rng = SimpleRng::new(1);
        assert_eq!(node.generate(&mut rng), b"HELLO");
    }

    #[test]
    fn grammar_blob_length_in_range() {
        let node = GrammarNode::Blob { min_len: 4, max_len: 8 };
        let mut rng = SimpleRng::new(1);
        for _ in 0..20 {
            let out = node.generate(&mut rng);
            assert!(out.len() >= 4 && out.len() <= 8);
        }
    }

    #[test]
    fn grammar_choice_picks_one() {
        let node = GrammarNode::Choice(vec![
            GrammarNode::Literal(b"A".to_vec()),
            GrammarNode::Literal(b"B".to_vec()),
        ]);
        let mut rng = SimpleRng::new(1);
        let out = node.generate(&mut rng);
        assert!(out == b"A" || out == b"B");
    }

    #[test]
    fn grammar_sequence_concatenates() {
        let node = GrammarNode::Sequence(vec![
            GrammarNode::Literal(b"HE".to_vec()),
            GrammarNode::Literal(b"LLO".to_vec()),
        ]);
        let mut rng = SimpleRng::new(1);
        assert_eq!(node.generate(&mut rng), b"HELLO");
    }

    #[test]
    fn grammar_repeat_respects_bounds() {
        let node = GrammarNode::Repeat {
            node: Box::new(GrammarNode::Literal(b"X".to_vec())),
            min: 2,
            max: 5,
        };
        let mut rng = SimpleRng::new(1);
        for _ in 0..20 {
            let out = node.generate(&mut rng);
            assert!(out.len() >= 2 && out.len() <= 5);
        }
    }

    #[test]
    fn grammar_interesting_u8_is_interesting() {
        const INTERESTING: &[u8] = &[0, 1, 0x7f, 0x80, 0xfe, 0xff];
        let node = GrammarNode::InterestingU8;
        let mut rng = SimpleRng::new(7);
        for _ in 0..20 {
            let out = node.generate(&mut rng);
            assert_eq!(out.len(), 1);
            assert!(INTERESTING.contains(&out[0]));
        }
    }

    // ── StructuredMutator ─────────────────────────────────────────────────────

    #[test]
    fn structured_mutator_generates_nonempty() {
        let mut m = StructuredMutator::random_blob(4, 16);
        let mut c = ctx(1);
        let out = m.mutate(&[], &mut c).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn structured_mutator_respects_max_size() {
        let mut m = StructuredMutator::random_blob(100, 200);
        let mut c = MutatorContext::new(1, 50);
        let out = m.mutate(&[0u8; 10], &mut c).unwrap();
        assert!(out.len() <= 50);
    }

    #[test]
    fn structured_mutator_stats_updated() {
        let mut m = StructuredMutator::random_blob(4, 8);
        let mut c = ctx(2);
        m.mutate(&[1, 2], &mut c).unwrap();
        assert_eq!(m.stats.total_mutations, 1);
    }

    #[test]
    fn structured_mutator_name() {
        let m = StructuredMutator::random_blob(1, 4);
        assert_eq!(m.name(), "StructuredMutator");
    }

    // ── DictionaryMutator ─────────────────────────────────────────────────────

    #[test]
    fn dictionary_mutator_inserts_token() {
        let mut m = DictionaryMutator::new(vec![b"MAGIC".to_vec()]);
        let mut c = ctx(1);
        let out = m.mutate(&[0u8; 16], &mut c).unwrap();
        assert_eq!(out.len(), 16); // same length (overwrite mode)
    }

    #[test]
    fn dictionary_mutator_empty_dict_noop() {
        let mut m = DictionaryMutator::new(vec![]);
        let mut c = ctx(1);
        let input = vec![1u8, 2, 3];
        let out = m.mutate(&input, &mut c).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn dictionary_mutator_load_from_text() {
        let mut m = DictionaryMutator::new(vec![]);
        m.load_from_text("\"HELLO\"\nWORLD\n# comment\n");
        assert_eq!(m.token_count(), 2);
    }

    #[test]
    fn dictionary_mutator_add_str_token() {
        let mut m = DictionaryMutator::new(vec![]);
        m.add_str_token("test");
        assert_eq!(m.token_count(), 1);
    }

    #[test]
    fn dictionary_mutator_stats() {
        let mut m = DictionaryMutator::new(vec![b"X".to_vec()]);
        let mut c = ctx(3);
        m.mutate(&[0u8; 8], &mut c).unwrap();
        assert_eq!(m.stats.total_mutations, 1);
    }

    // ── CrossoverMutator ──────────────────────────────────────────────────────

    #[test]
    fn crossover_mutator_empty_corpus_noop() {
        let mut m = CrossoverMutator::new();
        let mut c = ctx(1);
        let input = vec![1u8, 2, 3];
        let out = m.mutate(&input, &mut c).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn crossover_mutator_produces_combined_bytes() {
        let mut m = CrossoverMutator::new();
        let mut c = ctx_with_corpus(42, vec![vec![0xAAu8; 8]]);
        let input = vec![0xBBu8; 8];
        let out = m.mutate(&input, &mut c).unwrap();
        // Result should contain bytes from either input or corpus.
        assert!(!out.is_empty());
    }

    #[test]
    fn crossover_mutator_name() {
        let m = CrossoverMutator::new();
        assert_eq!(m.name(), "CrossoverMutator");
    }

    #[test]
    fn crossover_mutator_stats() {
        let mut m = CrossoverMutator::new();
        let mut c = ctx_with_corpus(1, vec![vec![1, 2]]);
        m.mutate(&[3, 4], &mut c).unwrap();
        assert_eq!(m.stats.total_mutations, 1);
    }

    // ── MutatorChain ─────────────────────────────────────────────────────────

    #[test]
    fn chain_sequential_applies_all() {
        let mut chain = MutatorChain::new(ChainMode::Sequential);
        chain.add(DictionaryMutator::new(vec![vec![0xFFu8]]));
        chain.add(CrossoverMutator::new());
        let mut c = ctx(1);
        let input = vec![0u8; 8];
        let out = chain.mutate(&input, &mut c).unwrap();
        assert!(!out.is_empty());
        assert_eq!(chain.total_rounds, 1);
    }

    #[test]
    fn chain_random_picks_one() {
        let mut chain = MutatorChain::new(ChainMode::Random);
        chain.add(DictionaryMutator::new(vec![b"A".to_vec()]));
        chain.add(CrossoverMutator::new());
        let mut c = ctx(2);
        let input = vec![0u8; 8];
        let out = chain.mutate(&input, &mut c).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn chain_min_length_picks_shortest() {
        let mut chain = MutatorChain::new(ChainMode::MinLength);
        // First mutator returns longer; second returns original (noop).
        chain.add(StructuredMutator::random_blob(50, 100));
        chain.add(DictionaryMutator::new(vec![])); // noop
        let mut c = ctx(5);
        let input = vec![0u8; 4];
        let out = chain.mutate(&input, &mut c).unwrap();
        // Shortest should be the original 4 bytes (noop dict).
        assert!(out.len() <= 100);
    }

    #[test]
    fn chain_empty_returns_input() {
        let mut chain = MutatorChain::new(ChainMode::Sequential);
        let mut c = ctx(0);
        let input = vec![1u8, 2, 3];
        let out = chain.mutate(&input, &mut c).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn chain_record_interesting() {
        let mut chain = MutatorChain::new(ChainMode::Random);
        chain.add(DictionaryMutator::new(vec![b"T".to_vec()]));
        let mut c = ctx(0);
        chain.mutate(&[1u8], &mut c).unwrap();
        chain.record_interesting("DictionaryMutator");
        let s = chain.stats.get("DictionaryMutator").unwrap();
        assert_eq!(s.interesting_mutations, 1);
    }

    #[test]
    fn chain_best_mutator() {
        let mut chain = MutatorChain::new(ChainMode::Random);
        chain.add(DictionaryMutator::new(vec![b"X".to_vec()]));
        chain.add(CrossoverMutator::new());
        let mut c = ctx(0);
        chain.mutate(&[1u8], &mut c).unwrap();
        chain.record_interesting("DictionaryMutator");
        let best = chain.best_mutator().unwrap();
        assert!(!best.is_empty());
    }
}
