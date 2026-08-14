//! Circuit-breaker for external services (e.g. PDB symbol server).
//!
//! After `max_failures` consecutive failures within `window`, the breaker
//! enters the **Open** state and rejects all calls immediately for
//! `open_duration`.  After that it enters **HalfOpen**: the next call is
//! allowed through; if it succeeds the breaker resets to **Closed**, otherwise
//! it re-opens for another `open_duration`.
//!
//! # Usage
//! ```no_run
//! use rustre_debug::circuit_breaker::CircuitBreaker;
//! use std::time::Duration;
//!
//! static PDB_CB: std::sync::LazyLock<CircuitBreaker> =
//!     std::sync::LazyLock::new(|| CircuitBreaker::new(3, Duration::from_secs(60)));
//!
//! fn download_pdb() -> Result<(), String> {
//!     PDB_CB.call(|| {
//!         // actual download attempt
//!         Ok::<(), std::io::Error>(())
//!     })
//! }
//! ```
//!
//! The closure's error type has to be named, as above. [`CircuitBreaker::call`]
//! always returns `Result<T, String>` — it formats whatever the operation failed
//! with — so nothing constrains `E` on the way in, and a bare `Ok(())` does not
//! compile (`E0283: type annotations needed`). This example used to carry that
//! bare `Ok(())`: it was never compiled, because nothing in this project runs
//! `cargo test --doc`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// States of the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Normal operation: calls pass through.
    Closed,
    /// Service is unhealthy: calls are rejected immediately.
    Open,
    /// One probe call is allowed to test recovery.
    HalfOpen,
}

/// Thread-safe circuit breaker.
pub struct CircuitBreaker {
    inner: Mutex<BreakerInner>,
    max_failures: u32,
    window: Duration,
    open_duration: Duration,
}

struct BreakerInner {
    state: BreakerState,
    failures: u32,
    window_start: Instant,
    opened_at: Option<Instant>,
    /// A half-open probe is running right now.
    ///
    /// The doc of [`BreakerState::HalfOpen`] says "ONE probe call is allowed",
    /// and nothing enforced it: `call` simply did not reject in HalfOpen, so
    /// every caller that arrived during that window ran `op()`. On a debugger
    /// resolving symbols from several threads that is the whole fleet hitting
    /// an already-unhealthy server at the same instant — the exact behaviour
    /// the breaker exists to prevent, reintroduced at the one moment the
    /// service is least able to take it.
    probe_in_flight: bool,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// - `max_failures`: consecutive failures within `open_duration` that trip
    ///   the breaker.
    /// - `open_duration`: how long the breaker stays Open (and HalfOpen probe
    ///   interval).
    #[must_use]
    pub fn new(max_failures: u32, open_duration: Duration) -> Self {
        Self {
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed,
                failures: 0,
                window_start: Instant::now(),
                opened_at: None,
                probe_in_flight: false,
            }),
            max_failures,
            window: open_duration,
            open_duration,
        }
    }

    /// Return the current state.
    #[must_use]
    pub fn state(&self) -> BreakerState {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        self.advance_state(&mut g);
        g.state
    }

    /// Return the current consecutive failure count.
    #[must_use]
    pub fn failure_count(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .failures
    }

    /// Execute `op`.
    ///
    /// - If the breaker is Open, returns `Err("circuit breaker open")`.
    /// - Otherwise calls `op` and records success/failure.
    ///
    /// # Errors
    /// Returns `Err(E)` from `op`, or the breaker-open error string when Open.
    pub fn call<T, E: std::fmt::Display>(
        &self,
        op: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, String> {
        let was_half_open;
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            self.advance_state(&mut g);
            was_half_open = g.state == BreakerState::HalfOpen;
            if g.state == BreakerState::Open {
                return Err(format!(
                    "circuit breaker open after {} failures (retry in {:.0?})",
                    g.failures,
                    self.open_duration
                        .checked_sub(g.opened_at.unwrap_or_else(Instant::now).elapsed())
                        .unwrap_or_default(),
                ));
            }
            if was_half_open {
                // One probe, not one per caller.
                if g.probe_in_flight {
                    return Err(
                        "circuit breaker half-open: a probe call is already in flight".to_string()
                    );
                }
                g.probe_in_flight = true;
            }
        }

        match op() {
            Ok(v) => {
                let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                g.failures = 0;
                g.state = BreakerState::Closed;
                g.probe_in_flight = false;
                Ok(v)
            }
            Err(e) => {
                let msg = e.to_string();
                let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                // A failed HALF-OPEN probe re-opens immediately, without
                // consulting the failure counter. Going through the counter
                // could never work here: `window == open_duration`, and we
                // only reach HalfOpen because `open_duration` elapsed, so the
                // window reset below always fires and drops `failures` back
                // to 1 — under `max_failures` for any threshold above 1. That
                // left the breaker HalfOpen, which `call` does not reject, so
                // an unhealthy service kept being hammered by every
                // subsequent call instead of being shielded by the breaker.
                if was_half_open {
                    g.failures = self.max_failures;
                    g.state = BreakerState::Open;
                    g.opened_at = Some(Instant::now());
                    g.window_start = Instant::now();
                    // Released so the NEXT half-open window gets its probe.
                    // Leaving it set would wedge the breaker shut forever: the
                    // service could recover and nothing would ever try it
                    // again.
                    g.probe_in_flight = false;
                    return Err(msg);
                }
                // Reset window counter if window elapsed.
                if g.window_start.elapsed() > self.window {
                    g.failures = 0;
                    g.window_start = Instant::now();
                }
                g.failures += 1;
                if g.failures >= self.max_failures {
                    g.state = BreakerState::Open;
                    g.opened_at = Some(Instant::now());
                }
                Err(msg)
            }
        }
    }

    fn advance_state(&self, g: &mut BreakerInner) {
        if g.state == BreakerState::Open {
            if let Some(opened) = g.opened_at {
                if opened.elapsed() >= self.open_duration {
                    g.state = BreakerState::HalfOpen;
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn trips_after_max_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            let _ = cb.call(|| Err::<(), &str>("err"));
        }
        assert_eq!(cb.state(), BreakerState::Open);
    }

    #[test]
    fn rejects_when_open() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        for _ in 0..2 {
            let _ = cb.call(|| Err::<(), &str>("err"));
        }
        let r = cb.call(|| Ok::<(), &str>(()));
        assert!(r.is_err(), "open breaker should reject");
        assert!(r.unwrap_err().contains("circuit breaker open"));
    }

    /// After `open_duration` the breaker goes HalfOpen and lets one probe
    /// through. If that probe FAILS the breaker must go straight back to
    /// Open — that is the entire point of the state.
    ///
    /// It did not: the window reset in the failure path fires here by
    /// construction (`window == open_duration`, and we only reach HalfOpen
    /// because `open_duration` elapsed), so `failures` was zeroed and then
    /// incremented back to 1 — below `max_failures`, leaving the breaker
    /// HalfOpen. HalfOpen is not rejected by `call`, so a dead service kept
    /// getting hammered by every subsequent call instead of being shielded.
    #[test]
    fn a_failed_half_open_probe_reopens_the_breaker() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(50));
        for _ in 0..2 {
            let _ = cb.call(|| Err::<(), &str>("err"));
        }
        assert_eq!(cb.state(), BreakerState::Open);

        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(cb.state(), BreakerState::HalfOpen, "should offer a probe");

        // The probe fails.
        let r = cb.call(|| Err::<(), &str>("still down"));
        assert!(r.is_err());
        assert_eq!(
            cb.state(),
            BreakerState::Open,
            "a failed probe must re-open the breaker, not leave it half-open"
        );

        // ...and while Open it must reject, rather than pass calls through.
        let r = cb.call(|| Ok::<(), &str>(()));
        assert!(r.is_err(), "re-opened breaker must reject");
        assert!(r.unwrap_err().contains("circuit breaker open"));
    }

    /// The mirror case: a SUCCESSFUL half-open probe closes the breaker.
    #[test]
    fn a_successful_half_open_probe_closes_the_breaker() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(50));
        for _ in 0..2 {
            let _ = cb.call(|| Err::<(), &str>("err"));
        }
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(cb.state(), BreakerState::HalfOpen);

        let r = cb.call(|| Ok::<u32, &str>(7));
        assert_eq!(r.unwrap(), 7);
        assert_eq!(cb.state(), BreakerState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn resets_on_success() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        let _ = cb.call(|| Err::<(), &str>("err"));
        let _ = cb.call(|| Ok::<(), &str>(()));
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    /// HalfOpen must admit exactly ONE probe, not one per caller.
    ///
    /// `BreakerState::HalfOpen` is documented as "one probe call is allowed to
    /// test recovery", and nothing enforced it: `call` only rejected in Open,
    /// so every caller arriving during the half-open window ran the operation.
    /// On a debugger resolving symbols from several threads that is the whole
    /// fleet hitting an already-unhealthy server at the same instant - exactly
    /// what the breaker exists to prevent, reintroduced at the moment the
    /// service is least able to take it.
    #[test]
    fn half_open_admits_one_probe_and_holds_the_rest_back() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(30));
        for _ in 0..2 {
            let _ = cb.call(|| Err::<(), &str>("down"));
        }
        assert_eq!(cb.state(), BreakerState::Open);
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(cb.state(), BreakerState::HalfOpen);

        // The probe runs, and while it is in flight a second caller is held
        // back. Re-entrancy models the concurrent case without threads: the
        // inner call happens while the outer probe is still running.
        let mut inner_result: Option<Result<(), String>> = None;
        let outer = cb.call(|| {
            inner_result = Some(cb.call(|| Ok::<(), &str>(())).map(|()| ()));
            Ok::<(), &str>(())
        });
        assert!(outer.is_ok(), "the probe itself must be allowed through");
        let held = inner_result.expect("the second caller must have been attempted");
        assert!(
            held.is_err(),
            "a second caller during the half-open probe must be turned away, got {held:?}"
        );

        // After a successful probe the breaker is closed and everyone passes.
        assert_eq!(cb.state(), BreakerState::Closed);
        assert!(cb.call(|| Ok::<(), &str>(())).is_ok());
    }

    /// A FAILED probe must release the slot, or the breaker wedges shut and
    /// the service can never be retried even after it recovers.
    #[test]
    fn a_failed_probe_releases_the_slot_for_the_next_window() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(30));
        for _ in 0..2 {
            let _ = cb.call(|| Err::<(), &str>("down"));
        }
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(cb.state(), BreakerState::HalfOpen);
        // The probe fails: back to Open.
        let _ = cb.call(|| Err::<(), &str>("still down"));
        assert_eq!(cb.state(), BreakerState::Open);

        // Next window: a probe must be admitted again, and succeed.
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(cb.state(), BreakerState::HalfOpen);
        assert!(
            cb.call(|| Ok::<(), &str>(())).is_ok(),
            "the next window must get its own probe; a stuck flag would shut the breaker forever"
        );
        assert_eq!(cb.state(), BreakerState::Closed);
    }

}
