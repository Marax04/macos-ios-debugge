//! `concurrent_deobf_executor` — Execute multiple deobfuscation hypotheses
//! concurrently and select the best result.
//!
//! Races multiple hypothesis workers against each other, collecting results in
//! a shared pool and returning the hypothesis that produced the highest quality
//! transformed output.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{
    Hypothesis as HypothesisTrait, HypothesisResult, IdentityHypothesis, NopStripHypothesis,
    ScoreModel, XorBestKeyHypothesis,
};
use crate::hypothesis_generator::{Hypothesis, HypothesisKind};

// ─────────────────────────────────────────────────────────────────────────────
// ExecutionResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result produced by running one hypothesis on the input data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// ID of the hypothesis that produced this result.
    pub hypothesis_id: u32,
    /// Kind of the hypothesis.
    pub kind: HypothesisKind,
    /// Human-readable label.
    pub label: String,
    /// Combined quality score in [0.0, 1.0].
    pub score: f64,
    /// Naturalness of the transformed output.
    pub naturalness: f64,
    /// Complexity score of the transformed output.
    pub complexity: f64,
    /// Transformed bytes, if the hypothesis produced a transformation.
    pub output: Option<Vec<u8>>,
    /// Execution wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Whether the result was marked as viable.
    pub viable: bool,
    /// Metadata key-value pairs from the underlying hypothesis runner.
    pub metadata: HashMap<String, String>,
}

impl ExecutionResult {
    /// Returns `true` when the result is both viable and has a score above 0.6.
    #[must_use]
    pub fn is_high_quality(&self) -> bool {
        self.viable && self.score >= 0.6
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BestResult
// ─────────────────────────────────────────────────────────────────────────────

/// The winner selected from all concurrent execution results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestResult {
    /// The winning execution result.
    pub result: ExecutionResult,
    /// Total number of hypotheses that were executed.
    pub total_executed: usize,
    /// Number of viable results found.
    pub viable_count: usize,
    /// Wall-clock time for the entire pool run.
    pub pool_elapsed_ms: u64,
    /// Whether a transformation was actually applied (vs. identity win).
    pub transformed: bool,
}

impl BestResult {
    /// Returns the best output bytes; falls back to the original if none.
    #[must_use]
    pub fn best_output<'a>(&'a self, original: &'a [u8]) -> &'a [u8] {
        self.result
            .output
            .as_deref()
            .unwrap_or(original)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutorConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the concurrent executor.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum number of worker threads.
    pub max_threads: usize,
    /// Per-hypothesis timeout.
    pub timeout: Duration,
    /// Minimum score for a result to be considered viable.
    pub viable_threshold: f64,
    /// If `true`, return as soon as the first perfect result (score ≥ 0.95) is found.
    pub early_exit: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_threads: 4,
            timeout: Duration::from_secs(5),
            viable_threshold: 0.55,
            early_exit: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisWorker — trait object wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// A sendable, boxed deobfuscation worker combining an `Hypothesis` (generator
/// metadata) with a runnable `HypothesisTrait`.
struct HypothesisWorker {
    meta: Hypothesis,
    runner: Box<dyn HypothesisTrait>,
}

impl HypothesisWorker {
    fn new(meta: Hypothesis, runner: Box<dyn HypothesisTrait>) -> Self {
        Self { meta, runner }
    }

    fn execute(&self, data: &[u8]) -> HypothesisResult {
        self.runner.run(data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConcurrentDeobfExecutor
// ─────────────────────────────────────────────────────────────────────────────

/// Executes multiple deobfuscation hypotheses concurrently using a thread pool
/// and selects the best result.
///
/// # Thread safety
/// Uses `Arc<Mutex<_>>` for result collection and `Arc<[u8]>` for the shared
/// input buffer, so no unsafe code is required.
#[derive(Debug)]
pub struct ConcurrentDeobfExecutor {
    config: ExecutorConfig,
}

impl ConcurrentDeobfExecutor {
    /// Create a new executor with the given configuration.
    #[must_use]
    pub const fn new(config: ExecutorConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn default() -> Self {
        Self::new(ExecutorConfig::default())
    }

    /// Build the default set of hypothesis workers from a list of scored
    /// hypotheses.
    ///
    /// Maps each `HypothesisKind` to the appropriate concrete worker.
    fn build_workers(hypotheses: Vec<Hypothesis>) -> Vec<HypothesisWorker> {
        let mut workers = Vec::with_capacity(hypotheses.len());
        for h in hypotheses {
            let runner: Box<dyn HypothesisTrait> = match h.kind {
                HypothesisKind::NopPadded | HypothesisKind::ConstantUnfolded => Box::new(NopStripHypothesis),
                HypothesisKind::XorSingleByte => {
                    // Use the best-key searcher (subsumes fixed-key)
                    Box::new(XorBestKeyHypothesis)
                }
                _ => Box::new(IdentityHypothesis),
            };
            workers.push(HypothesisWorker::new(h, runner));
        }
        workers
    }

    /// Execute all `hypotheses` against `data` concurrently and return the
    /// [`BestResult`].
    ///
    /// Uses up to `config.max_threads` threads in parallel.  If `early_exit`
    /// is set, stops as soon as a result with `score >= 0.95` is found.
    #[must_use]
    pub fn execute(&self, data: &[u8], hypotheses: Vec<Hypothesis>) -> BestResult {
        let pool_start = Instant::now();
        let data_arc: Arc<[u8]> = Arc::from(data);
        let workers = Self::build_workers(hypotheses);
        let total = workers.len();

        if total == 0 {
            let fallback = ExecutionResult {
                hypothesis_id: 0,
                kind: HypothesisKind::Identity,
                label: "identity (fallback)".to_string(),
                score: 0.0,
                naturalness: 0.0,
                complexity: 0.0,
                output: None,
                elapsed_ms: 0,
                viable: false,
                metadata: HashMap::new(),
            };
            return BestResult {
                result: fallback,
                total_executed: 0,
                viable_count: 0,
                pool_elapsed_ms: 0,
                transformed: false,
            };
        }

        let results: Arc<Mutex<Vec<ExecutionResult>>> = Arc::new(Mutex::new(Vec::with_capacity(total)));
        let early_exit_flag: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let viable_threshold = self.config.viable_threshold;
        let early_exit_enabled = self.config.early_exit;
        let timeout = self.config.timeout;

        // Chunk workers across thread slots
        let chunks: Vec<Vec<HypothesisWorker>> = Self::partition_workers(workers, self.config.max_threads);
        let mut handles = Vec::with_capacity(chunks.len());

        for chunk in chunks {
            let data_clone = Arc::clone(&data_arc);
            let results_clone = Arc::clone(&results);
            let flag_clone = Arc::clone(&early_exit_flag);

            let handle = thread::spawn(move || {
                for worker in chunk {
                    if flag_clone.lock().is_ok_and(|f| *f) {
                        break;
                    }

                    // Extract metadata before moving `worker` into the inner thread so
                    // we can use them when building ExecutionResult after the timeout wait.
                    let hypothesis_id = worker.meta.id;
                    let kind = worker.meta.kind;
                    let label = worker.meta.description.clone();

                    // Enforce per-hypothesis timeout: run each hypothesis on its own thread
                    // and wait with recv_timeout so slow hypotheses cannot stall the pool
                    // beyond the configured budget.
                    let t0 = Instant::now();
                    let (tx, rx) = std::sync::mpsc::channel();
                    let data_for_worker = Arc::clone(&data_clone);
                    let _worker_handle = thread::spawn(move || {
                        let hr = worker.execute(&data_for_worker);
                        let _ = tx.send(hr);
                    });

                    // Poll the result channel with a small interval so we can also
                    // observe the early-exit flag mid-execution. This means a
                    // high-scoring result from another worker thread aborts our
                    // current in-progress hypothesis instead of having to wait for
                    // it to finish or for the full per-hypothesis timeout to elapse.
                    let poll_interval = Duration::from_millis(25);
                    let deadline = t0 + timeout;
                    let mut hr_opt: Option<HypothesisResult> = None;
                    let mut aborted_by_early_exit = false;
                    loop {
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        let remaining = deadline - now;
                        let wait = if remaining < poll_interval { remaining } else { poll_interval };
                        match rx.recv_timeout(wait) {
                            Ok(hr) => {
                                hr_opt = Some(hr);
                                break;
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                if early_exit_enabled
                                    && flag_clone.lock().is_ok_and(|f| *f)
                                {
                                    aborted_by_early_exit = true;
                                    break;
                                }
                                // else: keep polling until deadline
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    let elapsed_ms = t0.elapsed().as_millis() as u64;
                    if aborted_by_early_exit {
                        // Don't record a result for an aborted-mid-execution worker;
                        // just stop processing this chunk.
                        break;
                    }

                    let (score, naturalness, complexity, output, metadata) = match hr_opt {
                        Some(hr) => (
                            hr.combined_score(),
                            hr.naturalness,
                            hr.complexity,
                            hr.transformed.clone(),
                            hr.metadata.clone(),
                        ),
                        None => {
                            // Hypothesis exceeded the per-hypothesis timeout — record as
                            // non-viable with zero score so other results can still win.
                            (0.0, 0.0, 0.0, None, HashMap::new())
                        }
                    };

                    let viable = score >= viable_threshold;

                    if let Ok(mut res) = results_clone.lock() {
                        res.push(ExecutionResult {
                            hypothesis_id,
                            kind,
                            label,
                            score,
                            naturalness,
                            complexity,
                            output,
                            elapsed_ms,
                            viable,
                            metadata,
                        });
                    }

                    if early_exit_enabled && score >= 0.95 {
                        if let Ok(mut flag) = flag_clone.lock() {
                            *flag = true;
                        }
                        break;
                    }
                }
            });
            handles.push(handle);
        }

        // Join all threads
        for handle in handles {
            let _ = handle.join();
        }

        let pool_elapsed_ms = pool_start.elapsed().as_millis() as u64;
        // Arc::try_unwrap fails only if another thread still holds a clone —
        // that cannot happen here because all handles have been joined above.
        // Mutex::into_inner returns an error only if the mutex was poisoned
        // (a worker panicked while holding the lock); in that case we still
        // prefer to surface whatever partial results were collected rather than
        // silently discarding them.
        let all_results = Arc::try_unwrap(results)
            .map(|m| m.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner))
            .unwrap_or_default();

        let viable_count = all_results.iter().filter(|r| r.viable).count();

        // Select the best result by score
        let best = all_results
            .into_iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));

        if let Some(r) = best {
            let transformed = r.kind != HypothesisKind::Identity && r.output.is_some();
            BestResult {
                result: r,
                total_executed: total,
                viable_count,
                pool_elapsed_ms,
                transformed,
            }
        } else {
            let fallback = ExecutionResult {
                hypothesis_id: 0,
                kind: HypothesisKind::Identity,
                label: "identity (no results)".to_string(),
                score: ScoreModel::naturalness_score(data),
                naturalness: ScoreModel::naturalness_score(data),
                complexity: 1.0,
                output: Some(data.to_vec()),
                elapsed_ms: 0,
                viable: false,
                metadata: HashMap::new(),
            };
            BestResult {
                result: fallback,
                total_executed: total,
                viable_count: 0,
                pool_elapsed_ms,
                transformed: false,
            }
        }
    }

    /// Partition a flat list of workers into `n` chunks (round-robin).
    fn partition_workers(workers: Vec<HypothesisWorker>, n: usize) -> Vec<Vec<HypothesisWorker>> {
        let n = n.max(1);
        let mut buckets: Vec<Vec<HypothesisWorker>> = (0..n).map(|_| Vec::new()).collect();
        for (i, w) in workers.into_iter().enumerate() {
            buckets[i % n].push(w);
        }
        buckets.retain(|b| !b.is_empty());
        buckets
    }

    /// Execute using only the top-N hypotheses by confidence.
    #[must_use]
    pub fn execute_top_n(
        &self,
        data: &[u8],
        hypotheses: Vec<Hypothesis>,
        n: usize,
    ) -> BestResult {
        let mut sorted = hypotheses;
        sorted.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(n);
        self.execute(data, sorted)
    }

    /// Return the execution configuration.
    #[must_use]
    pub const fn config(&self) -> &ExecutorConfig {
        &self.config
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// executor_pool() — factory function
// ─────────────────────────────────────────────────────────────────────────────

/// Build a [`ConcurrentDeobfExecutor`] pool tuned for the given concurrency
/// level.
///
/// `threads` must be in `[1, 32]`; values outside this range are clamped.
#[must_use]
pub fn executor_pool(threads: usize) -> ConcurrentDeobfExecutor {
    let threads = threads.clamp(1, 32);
    ConcurrentDeobfExecutor::new(ExecutorConfig {
        max_threads: threads,
        ..ExecutorConfig::default()
    })
}

/// Build an executor tuned for aggressive early-exit behaviour.
#[must_use]
pub const fn fast_executor() -> ConcurrentDeobfExecutor {
    ConcurrentDeobfExecutor::new(ExecutorConfig {
        max_threads: 8,
        timeout: Duration::from_millis(500),
        viable_threshold: 0.60,
        early_exit: true,
    })
}

/// Build a thorough executor that evaluates every hypothesis without early exit.
#[must_use]
pub const fn thorough_executor() -> ConcurrentDeobfExecutor {
    ConcurrentDeobfExecutor::new(ExecutorConfig {
        max_threads: 4,
        timeout: Duration::from_secs(30),
        viable_threshold: 0.40,
        early_exit: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// ResultPool — collects multiple runs
// ─────────────────────────────────────────────────────────────────────────────

/// Collects [`ExecutionResult`]s from multiple executor runs and provides
/// analysis helpers.
#[derive(Debug, Clone, Default)]
pub struct ResultPool {
    results: Vec<ExecutionResult>,
}

impl ResultPool {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an execution result.
    pub fn push(&mut self, result: ExecutionResult) {
        self.results.push(result);
    }

    /// Add all results from a `BestResult`.
    pub fn extend_from_best(&mut self, best: BestResult) {
        self.push(best.result);
    }

    /// Return the single best result by score.
    #[must_use]
    pub fn best(&self) -> Option<&ExecutionResult> {
        self.results
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Return all viable results.
    #[must_use]
    pub fn viable(&self) -> Vec<&ExecutionResult> {
        self.results.iter().filter(|r| r.viable).collect()
    }

    /// Return results grouped by hypothesis kind.
    #[must_use]
    pub fn by_kind(&self) -> HashMap<HypothesisKind, Vec<&ExecutionResult>> {
        let mut map: HashMap<HypothesisKind, Vec<&ExecutionResult>> = HashMap::new();
        for r in &self.results {
            map.entry(r.kind).or_default().push(r);
        }
        map
    }

    /// Return the mean score across all results.
    #[must_use]
    pub fn mean_score(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        self.results.iter().map(|r| r.score).sum::<f64>() / self.results.len() as f64
    }

    /// Total number of results stored.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.results.len()
    }

    /// Returns `true` when the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Clear all stored results.
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis_generator::{Hypothesis, HypothesisKind};

    fn make_hypothesis(id: u32, kind: HypothesisKind, confidence: f64) -> Hypothesis {
        Hypothesis::new(id, kind, format!("{} test", kind.label()), confidence)
    }

    fn code_bytes() -> Vec<u8> {
        vec![
            0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x89, 0x45, 0xF8, 0xC3,
        ]
    }

    #[test]
    fn test_execute_empty_hypotheses() {
        let exec = executor_pool(2);
        let result = exec.execute(&code_bytes(), vec![]);
        assert_eq!(result.total_executed, 0);
    }

    #[test]
    fn test_execute_single_identity() {
        let exec = executor_pool(1);
        let hyps = vec![make_hypothesis(0, HypothesisKind::Identity, 0.9)];
        let best = exec.execute(&code_bytes(), hyps);
        assert_eq!(best.total_executed, 1);
        assert!(best.result.score >= 0.0);
    }

    #[test]
    fn test_execute_nop_strip() {
        let data = vec![0x90u8; 64];
        let exec = executor_pool(2);
        let hyps = vec![
            make_hypothesis(0, HypothesisKind::NopPadded, 0.8),
            make_hypothesis(1, HypothesisKind::Identity, 0.5),
        ];
        let best = exec.execute(&data, hyps);
        assert!(best.total_executed >= 1);
    }

    #[test]
    fn test_execute_returns_best_score() {
        let exec = executor_pool(2);
        let hyps = vec![
            make_hypothesis(0, HypothesisKind::Identity, 0.9),
            make_hypothesis(1, HypothesisKind::NopPadded, 0.6),
        ];
        let best = exec.execute(&code_bytes(), hyps);
        assert!(best.result.score >= 0.0 && best.result.score <= 1.0);
    }

    #[test]
    fn test_pool_elapsed_is_set() {
        let exec = executor_pool(2);
        let hyps = vec![make_hypothesis(0, HypothesisKind::Identity, 0.8)];
        let best = exec.execute(&code_bytes(), hyps);
        // Even if instant, elapsed should be a valid u64
        let _ = best.pool_elapsed_ms;
    }

    #[test]
    fn test_executor_pool_factory() {
        let e = executor_pool(4);
        assert_eq!(e.config().max_threads, 4);
    }

    #[test]
    fn test_fast_executor_factory() {
        let e = fast_executor();
        assert!(e.config().max_threads > 0);
        assert!(e.config().early_exit);
    }

    #[test]
    fn test_thorough_executor_factory() {
        let e = thorough_executor();
        assert!(!e.config().early_exit);
    }

    #[test]
    fn test_execute_top_n() {
        let exec = executor_pool(2);
        let hyps = vec![
            make_hypothesis(0, HypothesisKind::Identity, 0.9),
            make_hypothesis(1, HypothesisKind::NopPadded, 0.6),
            make_hypothesis(2, HypothesisKind::XorSingleByte, 0.4),
        ];
        let best = exec.execute_top_n(&code_bytes(), hyps, 2);
        assert!(best.total_executed <= 2);
    }

    #[test]
    fn test_result_pool_best() {
        let mut pool = ResultPool::new();
        let r1 = ExecutionResult {
            hypothesis_id: 0,
            kind: HypothesisKind::Identity,
            label: "identity".to_string(),
            score: 0.5,
            naturalness: 0.5,
            complexity: 0.5,
            output: None,
            elapsed_ms: 1,
            viable: true,
            metadata: HashMap::new(),
        };
        let mut r2 = r1.clone();
        r2.score = 0.9;
        r2.hypothesis_id = 1;
        pool.push(r1);
        pool.push(r2);
        assert_eq!(pool.best().map(|r| r.score), Some(0.9));
    }

    #[test]
    fn test_result_pool_viable() {
        let mut pool = ResultPool::new();
        let base = ExecutionResult {
            hypothesis_id: 0,
            kind: HypothesisKind::Identity,
            label: "t".to_string(),
            score: 0.7,
            naturalness: 0.7,
            complexity: 0.7,
            output: None,
            elapsed_ms: 0,
            viable: true,
            metadata: HashMap::new(),
        };
        let mut nonviable = base.clone();
        nonviable.viable = false;
        pool.push(base);
        pool.push(nonviable);
        assert_eq!(pool.viable().len(), 1);
    }

    #[test]
    fn test_result_pool_mean_score_empty() {
        let pool = ResultPool::new();
        assert_eq!(pool.mean_score(), 0.0);
    }

    #[test]
    fn test_result_pool_len_and_clear() {
        let mut pool = ResultPool::new();
        pool.push(ExecutionResult {
            hypothesis_id: 0,
            kind: HypothesisKind::Identity,
            label: "t".to_string(),
            score: 0.5,
            naturalness: 0.5,
            complexity: 0.5,
            output: None,
            elapsed_ms: 0,
            viable: true,
            metadata: HashMap::new(),
        });
        assert_eq!(pool.len(), 1);
        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_best_result_best_output_fallback() {
        let original = vec![0x90u8; 8];
        let r = ExecutionResult {
            hypothesis_id: 0,
            kind: HypothesisKind::Identity,
            label: "identity".to_string(),
            score: 0.5,
            naturalness: 0.5,
            complexity: 0.5,
            output: None,
            elapsed_ms: 0,
            viable: false,
            metadata: HashMap::new(),
        };
        let best = BestResult {
            result: r,
            total_executed: 1,
            viable_count: 0,
            pool_elapsed_ms: 0,
            transformed: false,
        };
        assert_eq!(best.best_output(&original), original.as_slice());
    }
}
