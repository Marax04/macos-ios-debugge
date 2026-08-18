//! Adversarial testing component for the IADL deobfuscation loop.
//!
//! The adversarial tester generates test cases designed to expose gaps in the
//! deobfuscation quality.  It operates by mutating a reference input set and
//! scoring the deobfuscated output against an equivalence oracle.
//!
//! Key types:
//! - [`TestCase`]          — an individual test input with expected output.
//! - [`Equivalence`]       — a verdict comparing original and deobfuscated behaviour.
//! - [`MutationOp`]        — an atomic mutation applied to a test case.
//! - [`AdversarialScore`]  — aggregated score for one round of testing.
//! - [`AdversarialTester`] — the main tester struct.

use std::collections::{BTreeMap, VecDeque};

// ---------------------------------------------------------------------------
// TestCase
// ---------------------------------------------------------------------------

/// A single test case: a byte-level input vector together with the expected
/// output of the *original* (obfuscated) function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCase {
    /// Unique identifier for this test case.
    pub id: u64,
    /// Raw input bytes.
    pub input: Vec<u8>,
    /// Expected output bytes (from the ground-truth / reference execution).
    pub expected_output: Vec<u8>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Generation that produced this test case (0 = seed).
    pub generation: u32,
    /// Parent test-case ID (0 for seeds).
    pub parent_id: u64,
}

impl TestCase {
    /// Create a seed test case (generation 0).
    #[must_use]
    pub const fn seed(id: u64, input: Vec<u8>, expected_output: Vec<u8>) -> Self {
        Self {
            id,
            input,
            expected_output,
            label: None,
            generation: 0,
            parent_id: 0,
        }
    }

    /// Create a derived test case by applying a mutation.
    #[must_use]
    pub const fn derived(
        id: u64,
        input: Vec<u8>,
        expected_output: Vec<u8>,
        parent: &TestCase,
    ) -> Self {
        Self {
            id,
            input,
            expected_output,
            label: None,
            generation: parent.generation + 1,
            parent_id: parent.id,
        }
    }

    /// Length of the input.
    #[must_use]
    pub const fn input_len(&self) -> usize {
        self.input.len()
    }
}

// ---------------------------------------------------------------------------
// Equivalence
// ---------------------------------------------------------------------------

/// Verdict of comparing the original and deobfuscated function outputs.
#[derive(Debug, Clone, PartialEq)]
pub struct Equivalence {
    /// Test case that generated this verdict.
    pub test_case_id: u64,
    /// Whether the outputs matched.
    pub matched: bool,
    /// Hamming distance between actual and expected outputs (0 if matched).
    pub hamming_distance: u32,
    /// Actual output produced by the deobfuscated function.
    pub actual_output: Vec<u8>,
    /// Optional diagnostics from the comparator.
    pub diagnostics: BTreeMap<String, f64>,
}

impl Equivalence {
    /// Construct a successful (matched) equivalence verdict.
    #[must_use]
    pub const fn pass(test_case_id: u64, output: Vec<u8>) -> Self {
        Self {
            test_case_id,
            matched: true,
            hamming_distance: 0,
            actual_output: output,
            diagnostics: BTreeMap::new(),
        }
    }

    /// Construct a failing equivalence verdict with Hamming distance.
    #[must_use]
    pub fn fail(test_case_id: u64, expected: &[u8], actual: Vec<u8>) -> Self {
        let dist = Self::hamming(expected, &actual);
        Self {
            test_case_id,
            matched: false,
            hamming_distance: dist,
            actual_output: actual,
            diagnostics: BTreeMap::new(),
        }
    }

    fn hamming(a: &[u8], b: &[u8]) -> u32 {
        let common = a.len().min(b.len());
        let mut dist = 0u32;
        for i in 0..common {
            // Use saturating_add: large inputs (≥512 MB) would otherwise overflow u32.
            dist = dist.saturating_add((a[i] ^ b[i]).count_ones());
        }
        // Extra bytes in the longer sequence contribute 8 bits each.
        // Guard both the cast and the multiply against overflow.
        let extra = (a.len().max(b.len()) - common)
            .try_into()
            .unwrap_or(u32::MAX / 8)
            .saturating_mul(8u32);
        dist.saturating_add(extra)
    }
}

// ---------------------------------------------------------------------------
// MutationOp
// ---------------------------------------------------------------------------

/// An atomic mutation applied to a [`TestCase`] input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationOp {
    /// Flip a single bit at position `bit_offset`.
    BitFlip { bit_offset: usize },
    /// Replace the byte at `byte_offset` with `value`.
    ByteSet { byte_offset: usize, value: u8 },
    /// XOR the byte at `byte_offset` with `mask`.
    ByteXor { byte_offset: usize, mask: u8 },
    /// Insert a byte `value` before position `byte_offset`.
    ByteInsert { byte_offset: usize, value: u8 },
    /// Delete the byte at `byte_offset`.
    ByteDelete { byte_offset: usize },
    /// Replace a 4-byte window starting at `offset` with `value` (LE).
    DwordSet { offset: usize, value: u32 },
    /// Append `bytes` at the end of the input.
    Append { bytes: Vec<u8> },
    /// Truncate input to the first `len` bytes.
    Truncate { len: usize },
}

impl MutationOp {
    /// Apply this mutation to `input`, returning the mutated bytes.
    #[must_use]
    pub fn apply(&self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        match self {
            MutationOp::BitFlip { bit_offset } => {
                let byte = bit_offset / 8;
                let bit = bit_offset % 8;
                if byte < out.len() {
                    out[byte] ^= 1 << bit;
                }
            }
            MutationOp::ByteSet { byte_offset, value } => {
                if *byte_offset < out.len() {
                    out[*byte_offset] = *value;
                }
            }
            MutationOp::ByteXor { byte_offset, mask } => {
                if *byte_offset < out.len() {
                    out[*byte_offset] ^= mask;
                }
            }
            MutationOp::ByteInsert { byte_offset, value } => {
                let pos = (*byte_offset).min(out.len());
                out.insert(pos, *value);
            }
            MutationOp::ByteDelete { byte_offset } => {
                if *byte_offset < out.len() {
                    out.remove(*byte_offset);
                }
            }
            MutationOp::DwordSet { offset, value } => {
                if *offset + 4 <= out.len() {
                    out[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            MutationOp::Append { bytes } => {
                out.extend_from_slice(bytes);
            }
            MutationOp::Truncate { len } => {
                out.truncate(*len);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// AdversarialScore
// ---------------------------------------------------------------------------

/// Aggregated score for one round of adversarial testing.
#[derive(Debug, Clone)]
pub struct AdversarialScore {
    /// Total test cases evaluated in this round.
    pub total: u32,
    /// Number of test cases that passed equivalence.
    pub passed: u32,
    /// Number of test cases that failed equivalence.
    pub failed: u32,
    /// Pass rate (0.0–1.0).
    pub pass_rate: f64,
    /// Mean Hamming distance for failing cases.
    pub mean_hamming: f64,
    /// Maximum Hamming distance observed.
    pub max_hamming: u32,
    /// Adversarial quality score: 1.0 = perfectly equivalent.
    pub adversarial_score: f64,
}

impl AdversarialScore {
    /// Compute from a slice of equivalence verdicts.
    #[must_use]
    pub fn from_verdicts(verdicts: &[Equivalence]) -> Self {
        if verdicts.is_empty() {
            return Self {
                total: 0,
                passed: 0,
                failed: 0,
                pass_rate: 1.0,
                mean_hamming: 0.0,
                max_hamming: 0,
                adversarial_score: 1.0,
            };
        }
        let total = verdicts.len() as u32;
        let passed = verdicts.iter().filter(|v| v.matched).count() as u32;
        let failed = total - passed;
        let pass_rate = f64::from(passed) / f64::from(total);
        let failing: Vec<u32> =
            verdicts.iter().filter(|v| !v.matched).map(|v| v.hamming_distance).collect();
        let mean_hamming = if failing.is_empty() {
            0.0
        } else {
            f64::from(failing.iter().sum::<u32>()) / failing.len() as f64
        };
        let max_hamming = failing.iter().copied().max().unwrap_or(0);
        // Adversarial score: pass_rate, penalised by normalised mean hamming.
        // We normalise by 8 * (max_expected_length = 64 bytes = 512 bits).
        let hamming_penalty = (mean_hamming / 512.0).min(1.0);
        let adversarial_score = pass_rate * (1.0 - hamming_penalty);

        Self { total, passed, failed, pass_rate, mean_hamming, max_hamming, adversarial_score }
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "AdversarialScore: {}/{} passed ({:.1}%), score={:.4}, mean_hamming={:.1}",
            self.passed, self.total, self.pass_rate * 100.0,
            self.adversarial_score, self.mean_hamming
        )
    }
}

/// Convenience function: compute adversarial score from verdicts.
#[must_use]
pub fn adversarial_score(verdicts: &[Equivalence]) -> f64 {
    AdversarialScore::from_verdicts(verdicts).adversarial_score
}

// ---------------------------------------------------------------------------
// AdversarialTester
// ---------------------------------------------------------------------------

/// Configuration for [`AdversarialTester`].
#[derive(Debug, Clone)]
pub struct TesterConfig {
    /// Maximum corpus size (oldest entries are evicted when full).
    pub max_corpus: usize,
    /// Number of mutations to generate per seed per round.
    pub mutations_per_seed: usize,
    /// Minimum pass rate required to consider a round successful.
    pub pass_threshold: f64,
    /// Maximum number of rounds per session.
    pub max_rounds: u32,
    /// Whether to retain failing test cases for subsequent rounds.
    pub retain_failures: bool,
}

impl Default for TesterConfig {
    fn default() -> Self {
        Self {
            max_corpus: 512,
            mutations_per_seed: 8,
            pass_threshold: 0.95,
            max_rounds: 16,
            retain_failures: true,
        }
    }
}

/// An oracle that evaluates a deobfuscated function on a given input.
///
/// Implementors should be pure (same input → same output) and cheap to call.
pub trait DeobfOracle: Send {
    /// Execute the deobfuscated function on `input` and return its output bytes.
    fn execute(&self, input: &[u8]) -> Vec<u8>;
}

/// The main adversarial tester.
///
/// Maintains a corpus of [`TestCase`]s, generates mutations, evaluates them
/// against a [`DeobfOracle`], and computes adversarial scores.
pub struct AdversarialTester {
    config: TesterConfig,
    corpus: VecDeque<TestCase>,
    next_id: u64,
    round: u32,
    history: Vec<AdversarialScore>,
    mutation_sequence: u64,
}

impl AdversarialTester {
    /// Create a new tester with the given configuration.
    #[must_use]
    pub const fn new(config: TesterConfig) -> Self {
        Self {
            config,
            corpus: VecDeque::new(),
            next_id: 1,
            round: 0,
            history: Vec::new(),
            mutation_sequence: 0,
        }
    }

    /// Add a seed test case to the corpus.
    pub fn add_seed(&mut self, input: Vec<u8>, expected_output: Vec<u8>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let tc = TestCase::seed(id, input, expected_output);
        self.add_to_corpus(tc);
        id
    }

    /// Run one adversarial round against the provided oracle.
    ///
    /// Returns the [`AdversarialScore`] for this round.
    pub fn run_round(&mut self, oracle: &dyn DeobfOracle) -> AdversarialScore {
        let seeds: Vec<TestCase> = self.corpus.iter().cloned().collect();
        let mut verdicts = Vec::new();

        for seed in &seeds {
            // Evaluate seed itself.
            let actual = oracle.execute(&seed.input);
            let v = if actual == seed.expected_output {
                Equivalence::pass(seed.id, actual)
            } else {
                Equivalence::fail(seed.id, &seed.expected_output, actual)
            };
            verdicts.push(v);

            // Generate mutations.
            for m in 0..self.config.mutations_per_seed {
                let op = self.deterministic_mutation(seed, m as u64);
                let mutated_input = op.apply(&seed.input);
                // For mutations, expected output is derived from the oracle on
                // the original function — here we use seed's expected as proxy.
                let mutated_expected = seed.expected_output.clone();
                let actual = oracle.execute(&mutated_input);
                let id = self.next_id;
                self.next_id += 1;
                let derived = TestCase::derived(id, mutated_input, mutated_expected.clone(), seed);

                let v = if actual == derived.expected_output {
                    Equivalence::pass(id, actual)
                } else {
                    Equivalence::fail(id, &derived.expected_output, actual)
                };

                if !v.matched && self.config.retain_failures {
                    self.add_to_corpus(derived);
                }
                verdicts.push(v);
            }
        }

        let score = AdversarialScore::from_verdicts(&verdicts);
        self.history.push(score.clone());
        self.round += 1;
        score
    }

    /// Run up to `max_rounds` rounds, stopping when `pass_threshold` is met.
    pub fn run_until_pass(&mut self, oracle: &dyn DeobfOracle) -> Vec<AdversarialScore> {
        let mut scores = Vec::new();
        for _ in 0..self.config.max_rounds {
            let score = self.run_round(oracle);
            let done = score.pass_rate >= self.config.pass_threshold;
            scores.push(score);
            if done {
                break;
            }
        }
        scores
    }

    /// Current corpus size.
    #[must_use]
    pub fn corpus_size(&self) -> usize {
        self.corpus.len()
    }

    /// All round scores recorded so far.
    #[must_use]
    pub fn history(&self) -> &[AdversarialScore] {
        &self.history
    }

    /// Reset the tester (corpus + history).
    pub fn reset(&mut self) {
        self.corpus.clear();
        self.next_id = 1;
        self.round = 0;
        self.history.clear();
        self.mutation_sequence = 0;
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn add_to_corpus(&mut self, tc: TestCase) {
        if self.corpus.len() >= self.config.max_corpus {
            self.corpus.pop_front();
        }
        self.corpus.push_back(tc);
    }

    fn deterministic_mutation(&mut self, seed: &TestCase, index: u64) -> MutationOp {
        self.mutation_sequence = self.mutation_sequence.wrapping_add(1);
        let seed_val = seed.id
            .wrapping_mul(2654435761)
            .wrapping_add(index)
            .wrapping_add(self.mutation_sequence);

        let len = seed.input.len();
        if len == 0 {
            return MutationOp::Append { bytes: vec![(seed_val & 0xFF) as u8] };
        }

        let byte_pos = (seed_val as usize) % len;
        let bit_pos = (seed_val as usize * 7) % (len * 8);
        match seed_val % 7 {
            0 => MutationOp::BitFlip { bit_offset: bit_pos },
            1 => MutationOp::ByteSet {
                byte_offset: byte_pos,
                value: ((seed_val >> 8) & 0xFF) as u8,
            },
            2 => MutationOp::ByteXor {
                byte_offset: byte_pos,
                mask: ((seed_val >> 16) & 0xFF) as u8,
            },
            3 if len > 1 => MutationOp::ByteDelete { byte_offset: byte_pos },
            4 => MutationOp::ByteInsert {
                byte_offset: byte_pos,
                value: ((seed_val >> 24) & 0xFF) as u8,
            },
            5 if len >= 4 => {
                let aligned = byte_pos & !3;
                let safe_pos = aligned.min(len - 4);
                MutationOp::DwordSet {
                    offset: safe_pos,
                    value: (seed_val >> 32) as u32,
                }
            }
            _ => MutationOp::Truncate { len: 1 + byte_pos },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityOracle;
    impl DeobfOracle for IdentityOracle {
        fn execute(&self, input: &[u8]) -> Vec<u8> {
            input.to_vec()
        }
    }

    struct ZeroOracle;
    impl DeobfOracle for ZeroOracle {
        fn execute(&self, input: &[u8]) -> Vec<u8> {
            vec![0u8; input.len()]
        }
    }

    #[test]
    fn test_mutation_op_bitflip() {
        let op = MutationOp::BitFlip { bit_offset: 0 };
        let out = op.apply(&[0b00000000]);
        assert_eq!(out, vec![0b00000001]);
    }

    #[test]
    fn test_mutation_op_byte_set() {
        let op = MutationOp::ByteSet { byte_offset: 1, value: 42 };
        let out = op.apply(&[1, 2, 3]);
        assert_eq!(out, vec![1, 42, 3]);
    }

    #[test]
    fn test_mutation_op_insert_delete() {
        let op = MutationOp::ByteInsert { byte_offset: 1, value: 99 };
        let out = op.apply(&[10, 20]);
        assert_eq!(out, vec![10, 99, 20]);

        let op2 = MutationOp::ByteDelete { byte_offset: 1 };
        let out2 = op2.apply(&out);
        assert_eq!(out2, vec![10, 20]);
    }

    #[test]
    fn test_equivalence_pass() {
        let v = Equivalence::pass(1, vec![1, 2, 3]);
        assert!(v.matched);
        assert_eq!(v.hamming_distance, 0);
    }

    #[test]
    fn test_equivalence_fail_hamming() {
        let expected = vec![0u8; 8];
        let actual = vec![0xFF; 8];
        let v = Equivalence::fail(1, &expected, actual);
        assert!(!v.matched);
        assert_eq!(v.hamming_distance, 64); // 8 bytes * 8 bits each
    }

    #[test]
    fn test_adversarial_score_all_pass() {
        let verdicts = vec![
            Equivalence::pass(1, vec![1]),
            Equivalence::pass(2, vec![2]),
        ];
        let score = AdversarialScore::from_verdicts(&verdicts);
        assert!((score.pass_rate - 1.0).abs() < 1e-9);
        assert_eq!(score.failed, 0);
    }

    #[test]
    fn test_adversarial_score_fn() {
        let verdicts = vec![Equivalence::pass(1, vec![1])];
        let s = adversarial_score(&verdicts);
        assert!(s > 0.0);
    }

    #[test]
    fn test_tester_identity_oracle() {
        let mut tester = AdversarialTester::new(TesterConfig::default());
        tester.add_seed(vec![1, 2, 3], vec![1, 2, 3]);
        let score = tester.run_round(&IdentityOracle);
        // IdentityOracle passes the seed itself; mutated inputs no longer match
        // the seed's expected output, so only the seed succeeds.
        assert!(score.passed >= 1);
        assert_eq!(score.total, 1 + TesterConfig::default().mutations_per_seed as u32);
    }

    #[test]
    fn test_tester_zero_oracle() {
        let mut tester = AdversarialTester::new(TesterConfig::default());
        tester.add_seed(vec![1, 2, 3], vec![1, 2, 3]);
        let score = tester.run_round(&ZeroOracle);
        assert!(score.failed > 0);
    }

    #[test]
    fn test_tester_reset() {
        let mut tester = AdversarialTester::new(TesterConfig::default());
        tester.add_seed(vec![1], vec![1]);
        tester.run_round(&IdentityOracle);
        tester.reset();
        assert_eq!(tester.corpus_size(), 0);
        assert!(tester.history().is_empty());
    }

    #[test]
    fn test_test_case_seed() {
        let tc = TestCase::seed(42, vec![0], vec![1]);
        assert_eq!(tc.id, 42);
        assert_eq!(tc.generation, 0);
        assert_eq!(tc.parent_id, 0);
    }

    #[test]
    fn test_adversarial_score_empty() {
        let s = AdversarialScore::from_verdicts(&[]);
        assert!((s.adversarial_score - 1.0).abs() < 1e-9);
    }
}
