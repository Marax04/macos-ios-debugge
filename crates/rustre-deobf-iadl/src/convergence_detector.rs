//! `convergence_detector` — convergence detection for the IADL loop.
//!
//! [`ConvergenceDetector`] inspects the rolling quality-score history and
//! detects:
//! - **Plateau**: no meaningful improvement over a sliding window.
//! - **Oscillation**: scores bouncing between two or more values.
//! - **Budget exhaustion**: maximum iteration count reached.
//!
//! When any of these states is detected the loop should stop.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// ConvergenceState
// ─────────────────────────────────────────────────────────────────────────────

/// The convergence status returned by [`ConvergenceDetector::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConvergenceState {
    /// The loop is still making progress; continue.
    Running,
    /// Scores have plateaued — no improvement over the detection window.
    Plateau,
    /// Scores are oscillating — improvement is not monotone.
    Oscillating,
    /// The maximum iteration count has been reached.
    BudgetExhausted,
}

impl std::fmt::Display for ConvergenceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => f.write_str("Running"),
            Self::Plateau => f.write_str("Plateau"),
            Self::Oscillating => f.write_str("Oscillating"),
            Self::BudgetExhausted => f.write_str("BudgetExhausted"),
        }
    }
}

impl ConvergenceState {
    /// Returns `true` if the loop should continue.
    #[must_use]
    pub fn should_continue(self) -> bool {
        self == Self::Running
    }

    /// Returns `true` if the loop has reached any terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        !self.should_continue()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConvergenceConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`ConvergenceDetector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceConfig {
    /// Number of iterations in the plateau-detection window.
    pub plateau_window: usize,
    /// Minimum improvement required over the window to not be considered a plateau.
    pub plateau_threshold: f64,
    /// Number of alternations required to flag oscillation.
    pub oscillation_count: usize,
    /// Maximum oscillation amplitude (score range) to consider as oscillation.
    pub oscillation_amplitude: f64,
    /// Absolute maximum iterations (hard budget guard).
    pub max_iterations: usize,
}

impl Default for ConvergenceConfig {
    fn default() -> Self {
        Self {
            plateau_window: 5,
            plateau_threshold: 1e-5,
            oscillation_count: 4,
            oscillation_amplitude: 0.02,
            max_iterations: 64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConvergenceDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects plateau, oscillation, and budget-exhaustion in a rolling score
/// history from the IADL loop.
///
/// # Usage
/// ```rust,no_run
/// use std::collections::VecDeque;
/// use rustre_deobf_iadl::convergence_detector::{ConvergenceDetector, ConvergenceState};
///
/// let mut det = ConvergenceDetector::new(64);
/// let mut history: VecDeque<f64> = VecDeque::new();
/// history.push_back(0.3);
/// history.push_back(0.3);
/// history.push_back(0.3);
/// history.push_back(0.3);
/// history.push_back(0.3);
/// assert_eq!(det.check(&history), ConvergenceState::Plateau);
/// ```
#[derive(Debug, Clone)]
pub struct ConvergenceDetector {
    config: ConvergenceConfig,
    iteration_count: usize,
}

impl ConvergenceDetector {
    /// Create a detector with default settings and the given max-iteration budget.
    #[must_use]
    pub fn new(max_iterations: usize) -> Self {
        Self {
            config: ConvergenceConfig {
                max_iterations,
                ..ConvergenceConfig::default()
            },
            iteration_count: 0,
        }
    }

    /// Create a detector from an explicit [`ConvergenceConfig`].
    #[must_use]
    pub const fn with_config(config: ConvergenceConfig) -> Self {
        Self {
            config,
            iteration_count: 0,
        }
    }

    /// Return the current configuration.
    #[must_use]
    pub const fn config(&self) -> &ConvergenceConfig {
        &self.config
    }

    /// Reset the iteration counter.
    pub const fn reset(&mut self) {
        self.iteration_count = 0;
    }

    /// Increment the iteration counter and check for convergence against
    /// `history`.
    ///
    /// This is the primary method called by [`IadlLoop`] each iteration.
    ///
    /// Returns [`ConvergenceState::Running`] if no terminal condition is met.
    ///
    /// [`IadlLoop`]: crate::adversarial_loop::IadlLoop
    pub fn check(&mut self, history: &VecDeque<f64>) -> ConvergenceState {
        self.iteration_count += 1;

        // Budget guard (checked before more expensive operations).
        if self.iteration_count >= self.config.max_iterations {
            return ConvergenceState::BudgetExhausted;
        }

        if history.len() < 2 {
            return ConvergenceState::Running;
        }

        if self.detect_plateau(history) {
            return ConvergenceState::Plateau;
        }

        if self.detect_oscillation(history) {
            return ConvergenceState::Oscillating;
        }

        ConvergenceState::Running
    }

    /// Non-destructive check against a frozen history (does not increment counter).
    #[must_use]
    pub fn check_pure(&self, history: &VecDeque<f64>) -> ConvergenceState {
        if self.iteration_count >= self.config.max_iterations {
            return ConvergenceState::BudgetExhausted;
        }
        if history.len() < 2 {
            return ConvergenceState::Running;
        }
        if self.detect_plateau(history) {
            return ConvergenceState::Plateau;
        }
        if self.detect_oscillation(history) {
            return ConvergenceState::Oscillating;
        }
        ConvergenceState::Running
    }

    // ── Detection sub-routines ────────────────────────────────────────────────

    /// Plateau: the range (max − min) in the last `plateau_window` scores is
    /// below `plateau_threshold`.
    fn detect_plateau(&self, history: &VecDeque<f64>) -> bool {
        let w = self.config.plateau_window;
        if history.len() < w {
            return false;
        }
        let max = history
            .iter()
            .rev()
            .take(w)
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let min = history
            .iter()
            .rev()
            .take(w)
            .copied()
            .fold(f64::INFINITY, f64::min);
        (max - min) < self.config.plateau_threshold
    }

    /// Oscillation: alternating increases and decreases over `oscillation_count`
    /// consecutive steps, with a total amplitude above `oscillation_amplitude`.
    fn detect_oscillation(&self, history: &VecDeque<f64>) -> bool {
        let n = self.config.oscillation_count;
        if history.len() < n + 1 {
            return false;
        }
        let window: Vec<f64> = history.iter().rev().take(n + 1).copied().collect();

        // Compute sign of consecutive diffs.
        let mut alternations = 0usize;
        let mut last_sign = 0i8;
        for pair in window.windows(2) {
            let diff = pair[0] - pair[1]; // reversed since we took rev()
            let sign: i8 = if diff > 1e-9 {
                1
            } else if diff < -1e-9 {
                -1
            } else {
                0
            };
            if sign != 0 && last_sign != 0 && sign != last_sign {
                alternations += 1;
            }
            if sign != 0 {
                last_sign = sign;
            }
        }

        if alternations < n / 2 {
            return false;
        }

        // Amplitude check.
        let max = window.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min = window.iter().copied().fold(f64::INFINITY, f64::min);
        (max - min) >= self.config.oscillation_amplitude
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plateau analysis helper
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse a complete history and return the first index at which a plateau
/// begins (if any).
///
/// Returns `None` if no plateau is found.
#[must_use]
pub fn find_plateau_start(history: &[f64], window: usize, threshold: f64) -> Option<usize> {
    if history.len() < window {
        return None;
    }
    for i in 0..=(history.len() - window) {
        let w = &history[i..i + window];
        let max = w.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min = w.iter().copied().fold(f64::INFINITY, f64::min);
        if (max - min) < threshold {
            return Some(i);
        }
    }
    None
}

/// Compute the moving average of a score history with the given window size.
#[must_use]
pub fn moving_average(history: &[f64], window: usize) -> Vec<f64> {
    if window == 0 || history.is_empty() {
        return Vec::new();
    }
    history
        .windows(window)
        .map(|w| w.iter().sum::<f64>() / w.len() as f64)
        .collect()
}

/// Compute the exponential moving average (EMA) of a score history.
///
/// `alpha` controls the smoothing factor (0 < alpha ≤ 1; 1 = no smoothing).
#[must_use]
pub fn exponential_moving_average(history: &[f64], alpha: f64) -> Vec<f64> {
    if history.is_empty() {
        return Vec::new();
    }
    let alpha = alpha.clamp(1e-12, 1.0);
    let mut ema = Vec::with_capacity(history.len());
    ema.push(history[0]);
    for &v in &history[1..] {
        let prev = *ema.last().unwrap();
        ema.push((1.0 - alpha).mul_add(prev, alpha * v));
    }
    ema
}

/// Return the trend slope of a history (positive = improving, negative = declining).
///
/// Uses ordinary least-squares linear regression.
#[must_use]
pub fn trend_slope(history: &[f64]) -> f64 {
    let n = history.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let x_mean = (n - 1.0) / 2.0;
    let y_mean: f64 = history.iter().sum::<f64>() / n;
    let num: f64 = history
        .iter()
        .enumerate()
        .map(|(i, &y)| (i as f64 - x_mean) * (y - y_mean))
        .sum();
    let den: f64 = (0..history.len())
        .map(|i| (i as f64 - x_mean).powi(2))
        .sum();
    if den.abs() < 1e-12 { 0.0 } else { num / den }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_history(values: &[f64]) -> VecDeque<f64> {
        values.iter().copied().collect()
    }

    #[test]
    fn test_plateau_detection() {
        let mut det = ConvergenceDetector::new(1000);
        let history = make_history(&[0.5, 0.5, 0.5, 0.5, 0.5]);
        assert_eq!(det.check(&history), ConvergenceState::Plateau);
    }

    #[test]
    fn test_running_on_monotone_increase() {
        let mut det = ConvergenceDetector::new(1000);
        let history = make_history(&[0.1, 0.2, 0.3, 0.4, 0.5]);
        assert_eq!(det.check(&history), ConvergenceState::Running);
    }

    #[test]
    fn test_budget_exhausted() {
        let mut det = ConvergenceDetector::new(3);
        let history = make_history(&[0.1, 0.2]);
        det.check(&history); // iter 1
        det.check(&history); // iter 2
        let state = det.check(&history); // iter 3 → exhausted
        assert_eq!(state, ConvergenceState::BudgetExhausted);
    }

    #[test]
    fn test_oscillation_detection() {
        let mut det = ConvergenceDetector::with_config(ConvergenceConfig {
            oscillation_count: 4,
            oscillation_amplitude: 0.01,
            max_iterations: 1000,
            plateau_window: 20, // large enough to not trigger plateau
            plateau_threshold: 1e-10,
        });
        // Alternating scores well above amplitude threshold
        let history = make_history(&[0.5, 0.55, 0.48, 0.56, 0.47, 0.55]);
        let state = det.check(&history);
        assert_eq!(state, ConvergenceState::Oscillating);
    }

    #[test]
    fn test_short_history_is_running() {
        let mut det = ConvergenceDetector::new(100);
        let history = make_history(&[0.5]);
        assert_eq!(det.check(&history), ConvergenceState::Running);
    }

    #[test]
    fn test_convergence_state_display() {
        assert_eq!(ConvergenceState::Running.to_string(), "Running");
        assert_eq!(ConvergenceState::Plateau.to_string(), "Plateau");
        assert_eq!(ConvergenceState::Oscillating.to_string(), "Oscillating");
        assert_eq!(
            ConvergenceState::BudgetExhausted.to_string(),
            "BudgetExhausted"
        );
    }

    #[test]
    fn test_should_continue_only_for_running() {
        assert!(ConvergenceState::Running.should_continue());
        assert!(!ConvergenceState::Plateau.should_continue());
        assert!(!ConvergenceState::Oscillating.should_continue());
        assert!(!ConvergenceState::BudgetExhausted.should_continue());
    }

    #[test]
    fn test_find_plateau_start() {
        let history = vec![0.1, 0.3, 0.5, 0.5, 0.5, 0.5, 0.5];
        let idx = find_plateau_start(&history, 4, 1e-5);
        assert_eq!(idx, Some(2), "plateau starts at index 2");
    }

    #[test]
    fn test_moving_average() {
        let history = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ma = moving_average(&history, 3);
        assert!((ma[0] - 2.0).abs() < 1e-9); // (1+2+3)/3
        assert!((ma[1] - 3.0).abs() < 1e-9); // (2+3+4)/3
        assert!((ma[2] - 4.0).abs() < 1e-9); // (3+4+5)/3
    }

    #[test]
    fn test_ema_convergence() {
        let history = vec![0.0, 0.0, 0.0, 0.0, 1.0];
        let ema = exponential_moving_average(&history, 0.5);
        // Last value should be influenced by the spike at index 4.
        assert!(ema[4] > 0.0);
        // EMA should be less than raw value.
        assert!(ema[4] < 1.0);
    }

    #[test]
    fn test_trend_slope_positive() {
        let history = vec![0.0, 0.1, 0.2, 0.3, 0.4];
        let slope = trend_slope(&history);
        assert!(slope > 0.0, "monotone increase should have positive slope");
    }

    #[test]
    fn test_trend_slope_negative() {
        let history = vec![0.4, 0.3, 0.2, 0.1, 0.0];
        let slope = trend_slope(&history);
        assert!(slope < 0.0, "monotone decrease should have negative slope");
    }

    #[test]
    fn test_trend_slope_flat() {
        let history = vec![0.5; 10];
        let slope = trend_slope(&history);
        assert!(
            slope.abs() < 1e-9,
            "flat history should have near-zero slope"
        );
    }

    #[test]
    fn test_ema_single_element() {
        let ema = exponential_moving_average(&[0.7], 0.5);
        assert_eq!(ema, vec![0.7]);
    }

    #[test]
    fn test_check_pure_does_not_increment() {
        let det = ConvergenceDetector::new(1000);
        let history = make_history(&[0.5, 0.5, 0.5, 0.5, 0.5]);
        let s1 = det.check_pure(&history);
        let s2 = det.check_pure(&history);
        assert_eq!(s1, s2);
    }
}
