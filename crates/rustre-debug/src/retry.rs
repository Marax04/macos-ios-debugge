//! Exponential-backoff retry helper for transient errors.
//!
//! Used for:
//! - rr subprocess GDB RSP TCP connect (`rr_backend`)
//! - PDB symbol server HTTP download (`pdb_symbol_server`)
//!
//! # Design
//! - Synchronous variant: blocks the caller thread.
//! - Async variant: yields via `tokio::time::sleep`.
//! - Both take a closure / async closure returning `Result<T, E>`.
//! - Only retries when `is_transient(e)` returns `true`; non-transient
//!   errors are forwarded immediately.

use std::time::Duration;

/// Retry `op` up to `max_tries` times with exponential back-off starting at
/// `initial_delay`.  The delay doubles each attempt (capped at 30 s).
///
/// `is_transient` gates whether an error causes a retry.  Non-transient errors
/// short-circuit and are returned immediately without consuming further retries.
///
/// Returns `Ok(T)` on the first success, or `Err(E)` from the last attempt.
///
/// `max_tries == 0` is treated as 1: the operation is always attempted at
/// least once. There is no way to return an `E` without calling `op`, so the
/// alternative would be a panic — which is what this function used to do. The
/// old doc comment claimed a zero was "prevented by passing a non-zero
/// literal" because the parameter is a `u32`; `u32` includes zero, so a
/// computed or configured count of 0 panicked at runtime instead.
pub fn retry_with_backoff<T, E, F>(
    max_tries: u32,
    initial_delay: Duration,
    is_transient: impl Fn(&E) -> bool,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let max_tries = max_tries.max(1);
    let mut delay = initial_delay;
    let mut last_err: Option<E> = None;
    for attempt in 0..max_tries {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !is_transient(&e) {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt + 1 < max_tries {
                    std::thread::sleep(delay);
                    // `saturating_mul`: a plain `delay * 2` panics on
                    // overflow, and the `.min` cap is applied only AFTER the
                    // multiply, so it cannot prevent it.
                    delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                }
            }
        }
    }
    // `max_tries.max(1)` above guarantees the loop ran at least once.
    Err(last_err.expect("retry_with_backoff: loop always runs at least once"))
}

/// Async variant of [`retry_with_backoff`].
///
/// # Errors
/// Returns the last error after all retries are exhausted, or the first
/// non-transient error.
pub async fn retry_with_backoff_async<T, E, Fut, F>(
    max_tries: u32,
    initial_delay: Duration,
    is_transient: impl Fn(&E) -> bool,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    // Same two fixes as the sync variant above: `max_tries == 0` used to
    // fall through to a panicking `expect`, and `delay * 2` panics on
    // overflow because the `.min` cap only applies after the multiply.
    let max_tries = max_tries.max(1);
    let mut delay = initial_delay;
    let mut last_err: Option<E> = None;
    for attempt in 0..max_tries {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !is_transient(&e) {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt + 1 < max_tries {
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                }
            }
        }
    }
    Err(last_err.expect("retry_with_backoff_async: loop always runs at least once"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `max_tries == 0` used to reach the `expect` with `last_err == None`
    /// and panic at runtime. The doc comment justified it as impossible
    /// because the parameter is a `u32` — but `u32` includes zero, so any
    /// computed or configured retry count of 0 crashed instead of running.
    #[test]
    fn zero_max_tries_attempts_once_instead_of_panicking() {
        let mut calls = 0;
        let result = retry_with_backoff(0, Duration::from_millis(1), |_: &&str| true, || {
            calls += 1;
            Err::<i32, &str>("boom")
        });
        assert_eq!(result.unwrap_err(), "boom");
        assert_eq!(calls, 1, "zero should degrade to a single attempt");

        // And it still returns the value when that single attempt succeeds.
        let ok = retry_with_backoff(0, Duration::from_millis(1), |_: &&str| true, || {
            Ok::<i32, &str>(9)
        });
        assert_eq!(ok.unwrap(), 9);
    }

    /// The back-off doubling was a plain `delay * 2`, which panics on
    /// `Duration` overflow — and the 30 s `.min` cap is applied only after
    /// the multiply, so it could never prevent it.
    #[test]
    fn huge_initial_delay_does_not_overflow_the_backoff() {
        let mut calls = 0;
        // Large enough that doubling overflows `Duration`.
        let absurd = Duration::new(u64::MAX / 2 + 1, 0);
        let result = retry_with_backoff(2, absurd, |_: &&str| false, || {
            calls += 1;
            Err::<i32, &str>("nope")
        });
        // Non-transient short-circuits before sleeping, so this must not
        // hang; the point is that computing the next delay cannot panic.
        assert_eq!(result.unwrap_err(), "nope");
        assert_eq!(calls, 1);
        assert_eq!(absurd.saturating_mul(2).min(Duration::from_secs(30)), Duration::from_secs(30));
    }

    #[test]
    fn succeeds_on_first_try() {
        let result = retry_with_backoff(3, Duration::from_millis(1), |_: &()| true, || Ok::<i32, ()>(42));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn retries_transient_then_succeeds() {
        let mut calls = 0u32;
        let result = retry_with_backoff(
            3,
            Duration::from_millis(1),
            |_: &&str| true,
            || {
                calls += 1;
                if calls < 3 { Err("transient") } else { Ok(99u32) }
            },
        );
        assert_eq!(result, Ok(99));
        assert_eq!(calls, 3);
    }

    #[test]
    fn non_transient_returns_immediately() {
        let mut calls = 0u32;
        let result = retry_with_backoff::<i32, &str, _>(
            5,
            Duration::from_millis(1),
            |_| false, // never transient
            || { calls += 1; Err("fatal") },
        );
        assert!(result.is_err());
        assert_eq!(calls, 1, "should not retry non-transient errors");
    }

    #[test]
    fn exhausts_retries() {
        let mut calls = 0u32;
        let result = retry_with_backoff::<i32, &str, _>(
            3,
            Duration::from_millis(1),
            |_| true,
            || { calls += 1; Err("keep failing") },
        );
        assert!(result.is_err());
        assert_eq!(calls, 3);
    }
}
