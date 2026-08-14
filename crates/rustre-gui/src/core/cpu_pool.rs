// ============================================================================
// core/cpu_pool.rs — Process-wide rayon ThreadPool capped at 60% of cores
//
// The analysis pipeline (sweep, listing, xref, strings, label demangle) runs
// on this single pool. We deliberately leave ~40% of the host's parallelism
// to the GUI thread, the task system, and the user's other work so the desktop
// stays responsive while a heavy load is in flight.
// ============================================================================

use std::sync::OnceLock;
use std::thread::available_parallelism;

use rayon::{ThreadPool, ThreadPoolBuilder};

/// Cached `ThreadPool`. Built lazily on first access; never rebuilt.
static POOL: OnceLock<ThreadPool> = OnceLock::new();

/// Number of logical cores the OS exposes (or 1 if the query fails).
#[inline]
pub fn available_cores() -> usize {
    available_parallelism().map(std::num::NonZero::get).unwrap_or(1)
}

/// Target thread count: all logical cores except one (reserved for the
/// GUI thread and async task system). On a 1-core box we still get 1
/// worker. The previous 60% cap was deliberately conservative — heavy
/// analysis on large binaries (200k+ functions, 200 GiB images) needs
/// every spare core, and the OS scheduler is happy to time-slice GUI
/// frames between rayon work-steal cycles.
#[inline]
pub fn target_threads() -> usize {
    let cores = available_cores();
    cores.saturating_sub(1).max(1)
}

/// Returns the shared rayon pool. The first call builds it.
pub fn cpu_pool() -> &'static ThreadPool {
    POOL.get_or_init(|| {
        let n = target_threads();
        match ThreadPoolBuilder::new()
            .num_threads(n)
            .thread_name(|i| format!("rustre-cpu-{i}"))
            .build()
        {
            Ok(p) => {
                eprintln!(
                    "[cpu_pool] built rayon pool: threads={n} available_cores={}",
                    available_cores()
                );
                p
            }
            Err(e) => {
                eprintln!("[cpu_pool] ThreadPoolBuilder failed: {e}; falling back to single thread");
                ThreadPoolBuilder::new()
                    .num_threads(1)
                    .build()
                    .expect("single-thread rayon pool must build")
            }
        }
    })
}
