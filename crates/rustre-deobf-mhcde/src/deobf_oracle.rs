//! Deobfuscation oracle: try all registered strategies, rank by quality,
//! return top results.
//!
//! [`DeobfOracle`] wraps a set of [`OracleStrategy`] implementations and,
//! given raw input bytes, evaluates each strategy, scores its output with
//! [`EntropyScorer`], and returns the highest-quality results as
//! [`OracleResult`]s.  [`CachingOracle`] adds a memoisation layer on top.

use ahash::AHashMap as HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::entropy_scorer::{CompositeScore, EntropyScorer};

// ─────────────────────────────────────────────────────────────────────────────
// OracleStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// A single deobfuscation strategy that the oracle can try.
///
/// Implementations are stateless and must be [`Send`] + [`Sync`] so they can
/// be stored in a shared oracle and probed from multiple threads.
pub trait OracleStrategy: std::fmt::Debug + Send + Sync {
    /// Short, unique strategy name.
    fn name(&self) -> &'static str;

    /// One-line description of the strategy.
    fn description(&self) -> &'static str;

    /// Attempt to decode `input` and return the decoded bytes.
    ///
    /// Returns `None` when the strategy is not applicable or decoding fails.
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>>;

    /// Quick pre-check: return `false` to skip this strategy entirely for
    /// `input`, saving time.  Default is always `true`.
    fn is_applicable(&self, _input: &[u8]) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in strategies
// ─────────────────────────────────────────────────────────────────────────────

/// Identity strategy — returns the input unchanged.  Used as the baseline.
#[derive(Debug, Clone, Default)]
pub struct IdentityStrategy;

impl OracleStrategy for IdentityStrategy {
    fn name(&self) -> &'static str {
        "identity"
    }
    fn description(&self) -> &'static str {
        "Return input unchanged (baseline)"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(input.to_vec())
    }
}

/// XOR all bytes with a fixed key.
#[derive(Debug, Clone)]
pub struct XorConstantStrategy {
    /// The XOR key.
    pub key: u8,
}

impl XorConstantStrategy {
    /// Create a strategy for the given key.
    #[must_use]
    pub const fn new(key: u8) -> Self {
        Self { key }
    }
}

impl OracleStrategy for XorConstantStrategy {
    fn name(&self) -> &'static str {
        "xor-constant"
    }
    fn description(&self) -> &'static str {
        "XOR all bytes with a fixed single-byte key"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        if self.key == 0 {
            return Some(input.to_vec()); // no-op
        }
        Some(input.iter().map(|&b| b ^ self.key).collect())
    }
}

/// Best-key single-byte XOR: try all 256 keys and pick the highest-scoring.
#[derive(Debug, Clone, Default)]
pub struct XorBestKeyStrategy;

impl OracleStrategy for XorBestKeyStrategy {
    fn name(&self) -> &'static str {
        "xor-best-key"
    }
    fn description(&self) -> &'static str {
        "Try all 256 single-byte XOR keys and return the best-scoring decode"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        if input.is_empty() {
            return None;
        }
        let scorer = EntropyScorer::new();
        let mut best_score = f32::NEG_INFINITY;
        let mut best: Vec<u8> = input.to_vec();

        for key in 0u8..=255 {
            let decoded: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
            let s = scorer.score(&decoded).composite;
            if s > best_score {
                best_score = s;
                best = decoded;
            }
        }
        Some(best)
    }

    fn is_applicable(&self, input: &[u8]) -> bool {
        !input.is_empty()
    }
}

/// NOT (bitwise complement) of all bytes.
#[derive(Debug, Clone, Default)]
pub struct BitwiseNotStrategy;

impl OracleStrategy for BitwiseNotStrategy {
    fn name(&self) -> &'static str {
        "bitwise-not"
    }
    fn description(&self) -> &'static str {
        "Flip all bits (bitwise NOT)"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(input.iter().map(|&b| !b).collect())
    }
}

/// Add a constant (byte addition mod 256).
#[derive(Debug, Clone)]
pub struct AddConstantStrategy {
    /// The constant to subtract (i.e. the encoder added this).
    pub delta: u8,
}

impl AddConstantStrategy {
    /// Create a strategy that undoes addition of `delta`.
    #[must_use]
    pub const fn new(delta: u8) -> Self {
        Self { delta }
    }
}

impl OracleStrategy for AddConstantStrategy {
    fn name(&self) -> &'static str {
        "add-constant"
    }
    fn description(&self) -> &'static str {
        "Subtract a constant from each byte (undo ADD obfuscation)"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(input.iter().map(|&b| b.wrapping_sub(self.delta)).collect())
    }
}

/// ROL-N undo strategy (apply ROR-N).
#[derive(Debug, Clone)]
pub struct RorUndoStrategy {
    /// Rotation amount in bits.
    pub rotation: u8,
}

impl RorUndoStrategy {
    /// Create a strategy to undo ROL of `rotation` bits.
    #[must_use]
    pub const fn new(rotation: u8) -> Self {
        Self {
            rotation: rotation & 7,
        }
    }

    fn ror(byte: u8, n: u8) -> u8 {
        let n = n & 7;
        if n == 0 {
            return byte;
        }
        byte.rotate_right(u32::from(n))
    }
}

impl OracleStrategy for RorUndoStrategy {
    fn name(&self) -> &'static str {
        "ror-undo"
    }
    fn description(&self) -> &'static str {
        "Undo ROL obfuscation by applying ROR"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(input.iter().map(|&b| Self::ror(b, self.rotation)).collect())
    }
}

/// Reverse the byte order (sometimes used as a simple scramble).
#[derive(Debug, Clone, Default)]
pub struct ReverseStrategy;

impl OracleStrategy for ReverseStrategy {
    fn name(&self) -> &'static str {
        "reverse"
    }
    fn description(&self) -> &'static str {
        "Reverse the byte order"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut out = input.to_vec();
        out.reverse();
        Some(out)
    }
}

/// Byte-swap pairs: swap every `(bytes[i], bytes[i+1])`.
#[derive(Debug, Clone, Default)]
pub struct ByteSwapPairsStrategy;

impl OracleStrategy for ByteSwapPairsStrategy {
    fn name(&self) -> &'static str {
        "byteswap-pairs"
    }
    fn description(&self) -> &'static str {
        "Swap consecutive byte pairs"
    }
    fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut out = input.to_vec();
        let mut i = 0;
        while i + 1 < out.len() {
            out.swap(i, i + 1);
            i += 2;
        }
        Some(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of applying one strategy and scoring the output.
#[derive(Debug, Clone)]
pub struct OracleResult {
    /// Name of the strategy that produced this result.
    pub strategy: String,
    /// Description of the strategy.
    pub description: String,
    /// Decoded bytes.
    pub decoded: Vec<u8>,
    /// Quality score from the [`EntropyScorer`].
    pub quality: CompositeScore,
}

impl OracleResult {
    /// Return the composite quality score.
    #[must_use]
    pub const fn score(&self) -> f32 {
        self.quality.composite
    }

    /// Return `true` when `score >= threshold`.
    #[must_use]
    pub fn is_good(&self, threshold: f32) -> bool {
        self.quality.is_good(threshold)
    }
}

impl std::fmt::Display for OracleResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] score={:.3} ({}) len={}",
            self.strategy,
            self.quality.composite,
            self.quality.tier(),
            self.decoded.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`DeobfOracle`] runs.
#[derive(Debug, Clone)]
pub struct OracleConfig {
    /// Maximum number of strategies to evaluate.  Strategies beyond this limit
    /// are skipped (lowest-priority first).
    pub max_strategies: usize,
    /// Maximum time to spend on a single oracle call.  `None` = unlimited.
    pub timeout: Option<Duration>,
    /// Minimum quality score for a result to be included in the output.
    pub min_quality_threshold: f32,
    /// Maximum number of results to return.
    pub top_k: usize,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            max_strategies: 64,
            timeout: Some(Duration::from_secs(5)),
            min_quality_threshold: 0.0,
            top_k: 5,
        }
    }
}

impl OracleConfig {
    /// Create a config with no limits.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_strategies: usize::MAX,
            timeout: None,
            min_quality_threshold: 0.0,
            top_k: usize::MAX,
        }
    }

    /// Set the minimum quality threshold.
    #[must_use]
    pub const fn with_min_quality(mut self, q: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. With NaN every comparison is false, so we
        // fall through to 0.0.
        self.min_quality_threshold = if q >= 1.0 {
            1.0
        } else if q > 0.0 {
            q
        } else {
            0.0
        };
        self
    }

    /// Set the top-k limit.
    #[must_use]
    pub fn with_top_k(mut self, k: usize) -> Self {
        self.top_k = k.max(1);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfOracle
// ─────────────────────────────────────────────────────────────────────────────

/// Oracle that tries all registered strategies and returns the top results.
pub struct DeobfOracle {
    strategies: Vec<Arc<dyn OracleStrategy>>,
    scorer: EntropyScorer,
    config: OracleConfig,
}

impl std::fmt::Debug for DeobfOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeobfOracle")
            .field("strategy_count", &self.strategies.len())
            .finish_non_exhaustive()
    }
}

impl DeobfOracle {
    /// Create an oracle with default strategies and configuration.
    #[must_use]
    pub fn new() -> Self {
        let mut oracle = Self {
            strategies: Vec::new(),
            scorer: EntropyScorer::new(),
            config: OracleConfig::default(),
        };
        oracle.register_defaults();
        oracle
    }

    /// Create an empty oracle (no strategies pre-registered).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            strategies: Vec::new(),
            scorer: EntropyScorer::new(),
            config: OracleConfig::default(),
        }
    }

    /// Create an oracle with a custom configuration.
    #[must_use]
    pub fn with_config(config: OracleConfig) -> Self {
        let mut oracle = Self {
            strategies: Vec::new(),
            scorer: EntropyScorer::new(),
            config,
        };
        oracle.register_defaults();
        oracle
    }

    /// Register a strategy.
    pub fn register(&mut self, strategy: Arc<dyn OracleStrategy>) {
        self.strategies.push(strategy);
    }

    /// Register the built-in default strategies.
    pub fn register_defaults(&mut self) {
        self.strategies.push(Arc::new(IdentityStrategy));
        self.strategies.push(Arc::new(XorBestKeyStrategy));
        self.strategies.push(Arc::new(BitwiseNotStrategy));
        self.strategies.push(Arc::new(ReverseStrategy));
        self.strategies.push(Arc::new(ByteSwapPairsStrategy));
        // Add a selection of XOR constant strategies.
        for key in [0x01u8, 0x41, 0x42, 0x55, 0xAA, 0xFF] {
            self.strategies
                .push(Arc::new(XorConstantStrategy::new(key)));
        }
        // Add ROR-undo strategies.
        for rot in [1u8, 2, 3, 4] {
            self.strategies.push(Arc::new(RorUndoStrategy::new(rot)));
        }
        // Add a few ADD-constant strategies.
        for delta in [1u8, 0x41, 0x80] {
            self.strategies
                .push(Arc::new(AddConstantStrategy::new(delta)));
        }
    }

    /// Try all applicable strategies on `input` and return the top results.
    ///
    /// Results are sorted by quality score descending.  Results below
    /// [`OracleConfig::min_quality_threshold`] are excluded.  At most
    /// [`OracleConfig::top_k`] results are returned.
    #[must_use]
    pub fn query(&self, input: &[u8]) -> Vec<OracleResult> {
        let deadline = self.config.timeout.map(|t| Instant::now() + t);
        let mut results = Vec::new();

        for strategy in self.strategies.iter().take(self.config.max_strategies) {
            if let Some(dl) = deadline
                && Instant::now() > dl
            {
                break;
            }

            if !strategy.is_applicable(input) {
                continue;
            }

            let decoded = match strategy.decode(input) {
                Some(d) => d,
                None => continue,
            };

            let quality = self.scorer.score(&decoded);
            if quality.composite < self.config.min_quality_threshold {
                continue;
            }

            results.push(OracleResult {
                strategy: strategy.name().to_owned(),
                description: strategy.description().to_owned(),
                decoded,
                quality,
            });
        }

        // Sort by composite score, descending.
        results.sort_by(|a, b| {
            b.quality
                .composite
                .partial_cmp(&a.quality.composite)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results.truncate(self.config.top_k);
        results
    }

    /// Return the single best result, or `None` when no strategy produces
    /// output above the minimum quality threshold.
    #[must_use]
    pub fn best(&self, input: &[u8]) -> Option<OracleResult> {
        self.query(input).into_iter().next()
    }

    /// Number of registered strategies.
    #[must_use]
    pub fn strategy_count(&self) -> usize {
        self.strategies.len()
    }

    /// Borrow the oracle's scorer.
    #[must_use]
    pub const fn scorer(&self) -> &EntropyScorer {
        &self.scorer
    }

    /// Borrow the oracle's config.
    #[must_use]
    pub const fn config(&self) -> &OracleConfig {
        &self.config
    }
}

impl Default for DeobfOracle {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CachingOracle
// ─────────────────────────────────────────────────────────────────────────────

/// Memoisation wrapper around [`DeobfOracle`].
///
/// Caches the best result for each unique input (keyed by SHA-256 of the
/// input).  Useful when the same buffer is queried repeatedly during an
/// iterative deobfuscation loop.
pub struct CachingOracle {
    inner: DeobfOracle,
    /// Map from SHA-256 hex string → best `OracleResult`.
    cache: RwLock<HashMap<String, Option<OracleResult>>>,
    /// Maximum cache entries.
    capacity: usize,
}

impl std::fmt::Debug for CachingOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let size = self.cache.read().map_or(0, |g| g.len());
        f.debug_struct("CachingOracle")
            .field("cache_entries", &size)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl CachingOracle {
    /// Create a caching oracle with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: DeobfOracle::new(),
            cache: RwLock::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Create from an existing oracle.
    #[must_use]
    pub fn from_oracle(oracle: DeobfOracle, capacity: usize) -> Self {
        Self {
            inner: oracle,
            cache: RwLock::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Query with caching.
    pub fn best(&self, input: &[u8]) -> Option<OracleResult> {
        let key = self.hash(input);

        // Fast path: cache hit.
        if let Ok(guard) = self.cache.read()
            && let Some(cached) = guard.get(&key)
        {
            return cached.clone();
        }

        // Slow path: compute.
        let result = self.inner.best(input);

        // Store in cache if under capacity.
        if let Ok(mut guard) = self.cache.write()
            && guard.len() < self.capacity
        {
            guard.insert(key, result.clone());
        }

        result
    }

    /// Number of cached entries.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.read().map_or(0, |g| g.len())
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Ok(mut guard) = self.cache.write() {
            guard.clear();
        }
    }

    /// Borrow the inner oracle.
    #[must_use]
    pub const fn oracle(&self) -> &DeobfOracle {
        &self.inner
    }

    fn hash(&self, data: &[u8]) -> String {
        // Simple FNV-1a 64-bit hash (no extra dependency).
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in data {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        format!("{hash:016x}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IdentityStrategy ─────────────────────────────────────────────────────

    #[test]
    fn test_identity_returns_input() {
        let s = IdentityStrategy;
        let input = b"hello world";
        assert_eq!(s.decode(input), Some(input.to_vec()));
    }

    // ── XorConstantStrategy ───────────────────────────────────────────────────

    #[test]
    fn test_xor_constant_roundtrip() {
        let s = XorConstantStrategy::new(0x42);
        let plain = b"Secret payload!";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
        let dec = s.decode(&enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_xor_zero_identity() {
        let s = XorConstantStrategy::new(0);
        let input = b"test";
        assert_eq!(s.decode(input), Some(b"test".to_vec()));
    }

    // ── XorBestKeyStrategy ────────────────────────────────────────────────────

    #[test]
    fn test_xor_best_key_recovers_text() {
        let plain = b"AAAAAABBBBBBCCCCCC";
        let key = 0x55u8;
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let s = XorBestKeyStrategy;
        let dec = s.decode(&enc).unwrap();
        // The best key should produce all printable ASCII.
        assert!(dec.iter().all(|&b| b.is_ascii_graphic() || b == b' '));
    }

    #[test]
    fn test_xor_best_key_empty_input() {
        let s = XorBestKeyStrategy;
        assert_eq!(s.decode(&[]), None);
    }

    // ── BitwiseNotStrategy ────────────────────────────────────────────────────

    #[test]
    fn test_bitwise_not_roundtrip() {
        let s = BitwiseNotStrategy;
        let input = vec![0xAA, 0x55, 0xFF, 0x00];
        let enc = s.decode(&input).unwrap();
        let dec = s.decode(&enc).unwrap();
        assert_eq!(dec, input);
    }

    // ── AddConstantStrategy ───────────────────────────────────────────────────

    #[test]
    fn test_add_constant_roundtrip() {
        let s = AddConstantStrategy::new(0x41);
        let plain = b"Hello!";
        let enc: Vec<u8> = plain.iter().map(|&b| b.wrapping_add(0x41)).collect();
        let dec = s.decode(&enc).unwrap();
        assert_eq!(dec, plain);
    }

    // ── RorUndoStrategy ───────────────────────────────────────────────────────

    #[test]
    fn test_ror_undo_roundtrip() {
        let rot = 3u8;
        let strategy = RorUndoStrategy::new(rot);
        let plain = vec![0x41, 0x42, 0x43, 0x44];
        // Encode with ROL.
        let encoded: Vec<u8> = plain
            .iter()
            .map(|&b: &u8| b.rotate_left(u32::from(rot)))
            .collect();
        let decoded = strategy.decode(&encoded).unwrap();
        assert_eq!(decoded, plain);
    }

    // ── ReverseStrategy ───────────────────────────────────────────────────────

    #[test]
    fn test_reverse_roundtrip() {
        let s = ReverseStrategy;
        let input = b"abcdef";
        let enc = s.decode(input).unwrap();
        let dec = s.decode(&enc).unwrap();
        assert_eq!(dec.as_slice(), input.as_ref());
    }

    // ── ByteSwapPairsStrategy ─────────────────────────────────────────────────

    #[test]
    fn test_byteswap_pairs_roundtrip() {
        let s = ByteSwapPairsStrategy;
        let input = b"ABCD";
        let enc = s.decode(input).unwrap();
        assert_eq!(enc, b"BADC");
        let dec = s.decode(&enc).unwrap();
        assert_eq!(dec.as_slice(), input.as_ref());
    }

    // ── OracleResult ──────────────────────────────────────────────────────────

    #[test]
    fn test_oracle_result_display() {
        let r = OracleResult {
            strategy: "identity".to_owned(),
            description: "test".to_owned(),
            decoded: b"hello".to_vec(),
            quality: CompositeScore {
                composite: 0.75,
                components: vec![],
                total_weight: 1.0,
            },
        };
        let s = r.to_string();
        assert!(s.contains("identity"));
        assert!(s.contains("0.750"));
    }

    #[test]
    fn test_oracle_result_is_good() {
        let r = OracleResult {
            strategy: "x".to_owned(),
            description: "x".to_owned(),
            decoded: vec![],
            quality: CompositeScore {
                composite: 0.8,
                components: vec![],
                total_weight: 1.0,
            },
        };
        assert!(r.is_good(0.7));
        assert!(!r.is_good(0.9));
    }

    // ── OracleConfig ─────────────────────────────────────────────────────────

    #[test]
    fn test_oracle_config_default() {
        let c = OracleConfig::default();
        assert!(c.top_k >= 1);
        assert!(c.max_strategies >= 1);
    }

    #[test]
    fn test_oracle_config_with_min_quality() {
        let c = OracleConfig::default().with_min_quality(0.5);
        assert!((c.min_quality_threshold - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_oracle_config_unlimited() {
        let c = OracleConfig::unlimited();
        assert_eq!(c.max_strategies, usize::MAX);
        assert!(c.timeout.is_none());
    }

    // ── DeobfOracle ───────────────────────────────────────────────────────────

    #[test]
    fn test_oracle_strategy_count() {
        let o = DeobfOracle::new();
        assert!(o.strategy_count() > 0);
    }

    #[test]
    fn test_oracle_query_returns_results() {
        let o = DeobfOracle::new();
        let results = o.query(b"Hello, World! This is a test string.");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_oracle_results_sorted_descending() {
        let o = DeobfOracle::new();
        let results = o.query(b"Hello World!");
        for w in results.windows(2) {
            assert!(w[0].score() >= w[1].score());
        }
    }

    #[test]
    fn test_oracle_best_returns_highest() {
        let o = DeobfOracle::new();
        let all = o.query(b"test data");
        if let Some(best) = o.best(b"test data")
            && let Some(first) = all.first()
        {
            assert!((best.score() - first.score()).abs() < 0.001);
        }
    }

    #[test]
    fn test_oracle_top_k_respected() {
        let config = OracleConfig::default().with_top_k(2);
        let o = DeobfOracle::with_config(config);
        let results = o.query(b"Some arbitrary bytes go here");
        assert!(results.len() <= 2);
    }

    #[test]
    fn test_oracle_min_quality_filter() {
        let config = OracleConfig::default().with_min_quality(1.0); // impossible threshold
        let o = DeobfOracle::with_config(config);
        let results = o.query(b"hello world");
        // With threshold=1.0 almost nothing should pass.
        for r in &results {
            assert!(r.score() >= 1.0);
        }
    }

    #[test]
    fn test_oracle_empty_input() {
        let o = DeobfOracle::new();
        // Empty input should not panic.
        let results = o.query(&[]);
        let _ = results; // may or may not be empty
    }

    #[test]
    fn test_oracle_register_custom_strategy() {
        let mut o = DeobfOracle::empty();
        o.register(Arc::new(IdentityStrategy));
        assert_eq!(o.strategy_count(), 1);
    }

    // ── CachingOracle ─────────────────────────────────────────────────────────

    #[test]
    fn test_caching_oracle_returns_result() {
        let c = CachingOracle::new(100);
        let r1 = c.best(b"hello world");
        assert!(r1.is_some());
    }

    #[test]
    fn test_caching_oracle_cache_hit() {
        let c = CachingOracle::new(100);
        let input = b"test data for caching";
        let _ = c.best(input);
        assert_eq!(c.cache_size(), 1);
        let _ = c.best(input); // should hit cache
        assert_eq!(c.cache_size(), 1); // no new entry
    }

    #[test]
    fn test_caching_oracle_clear_cache() {
        let c = CachingOracle::new(100);
        let _ = c.best(b"data");
        assert!(c.cache_size() > 0);
        c.clear_cache();
        assert_eq!(c.cache_size(), 0);
    }

    #[test]
    fn test_caching_oracle_capacity_respected() {
        let c = CachingOracle::new(2);
        let _ = c.best(b"input_one");
        let _ = c.best(b"input_two");
        let _ = c.best(b"input_three"); // should not store (at capacity)
        assert!(c.cache_size() <= 2);
    }

    #[test]
    fn test_caching_oracle_debug() {
        let c = CachingOracle::new(10);
        let _ = format!("{c:?}");
    }
}
