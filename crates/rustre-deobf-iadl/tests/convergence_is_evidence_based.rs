//! Convergence must be a claim about observed data, never a vacuous truth.
//!
//! `ConvergenceDetector::is_converged` asks whether every delta in the window is
//! below epsilon. `Iterator::all` on an empty window is true by definition, and
//! `window.len() >= window_size` holds trivially when `window_size` is zero — so
//! a detector configured that way reports convergence before it has seen a
//! single delta. `window_size` is a public field and `with_window` takes any
//! `usize` without validating it, so this is reachable from outside.
//!
//! A deobfuscation loop that believes it has converged stops immediately and
//! reports the input as fully deobfuscated, having done nothing.

use rustre_deobf_iadl::loop_orchestrator::ConvergenceDetector;

/// Convergence must never be reported before any delta has been observed.
#[test]
fn a_detector_that_has_seen_nothing_is_not_converged() {
    for window_size in [0usize, 1, 5] {
        let detector = ConvergenceDetector::new().with_window(window_size);
        assert!(
            !detector.is_converged(),
            "a detector with window_size {window_size} and no observations reported \
             convergence — `all()` over an empty window is vacuously true"
        );
    }
}

/// A window that is not yet full cannot support the claim either.
#[test]
fn a_partial_window_is_not_converged() {
    let mut detector = ConvergenceDetector::new().with_window(5);
    for i in 0..4 {
        let converged = detector.update(0.0);
        assert!(
            !converged,
            "converged after only {} observation(s) of a 5-wide window",
            i + 1
        );
    }
    // The fifth fills it, and only then may it converge.
    assert!(detector.update(0.0), "a full window of zero deltas must converge");
}

/// Deltas at rest converge; a large delta breaks it again.
#[test]
fn convergence_tracks_the_recent_deltas() {
    let mut detector = ConvergenceDetector::new().with_window(3);
    assert!(!detector.update(0.0));
    assert!(!detector.update(0.0));
    assert!(detector.update(0.0), "three zero deltas are a fixed point");

    // A large delta must un-converge it: the loop is moving again.
    assert!(
        !detector.update(100.0),
        "a delta of 100 was accepted as convergence"
    );
}

/// The sign of a delta cannot change the verdict.
///
/// `update` stores `delta.abs()`, so a score that collapses must be treated
/// exactly like one that climbs by the same amount. Derived from that
/// documented intent rather than restating the stored values: if the `.abs()`
/// were ever dropped, a large negative delta would slip under epsilon and a
/// collapsing score would read as converged.
#[test]
fn a_falling_score_is_not_mistaken_for_convergence() {
    for magnitude in [1.0f64, 10.0, 1e6] {
        let mut rising = ConvergenceDetector::new().with_window(3);
        let mut falling = ConvergenceDetector::new().with_window(3);

        let mut last_rising = false;
        let mut last_falling = false;
        for _ in 0..3 {
            last_rising = rising.update(magnitude);
            last_falling = falling.update(-magnitude);
        }

        assert_eq!(
            last_rising, last_falling,
            "a delta of -{magnitude} was judged differently from +{magnitude}"
        );
        assert!(
            !last_falling,
            "a repeated delta of -{magnitude} was reported as convergence"
        );
    }
}

/// Convergence is monotone in epsilon: loosening the threshold can only make
/// convergence easier, never harder.
///
/// A reversed comparison passes any single hand-picked example but cannot
/// survive this.
#[test]
fn convergence_is_monotone_in_epsilon() {
    let deltas = [0.5f64, 0.4, 0.45];

    let mut previous = false;
    for epsilon in [1e-9f64, 0.1, 0.44, 0.46, 0.5, 1.0, 1e6] {
        let mut detector = ConvergenceDetector::new().with_window(3);
        detector.epsilon = epsilon;
        let mut converged = false;
        for d in deltas {
            converged = detector.update(d);
        }
        assert!(
            converged || !previous,
            "epsilon {epsilon} did not converge although a stricter one did"
        );
        previous = converged;
    }
    assert!(previous, "an epsilon of 1e6 must accept deltas below 0.5");
}

/// A `NaN` delta must not be read as convergence.
#[test]
fn a_nan_delta_does_not_converge() {
    let mut detector = ConvergenceDetector::new().with_window(2);
    detector.epsilon = 1e6;
    detector.update(f64::NAN);
    assert!(
        !detector.update(f64::NAN),
        "NaN deltas were accepted as a fixed point"
    );
}
